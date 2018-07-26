#include "glo.h"

char    *lg_home;
int		fifo_fd_ismg_send;
int		fifo_fd_ismg_recv;
int		fifo_fd_db;
int		log_fd_ismg_send;
int		log_fd_ismg_recv;
int		log_fd_db;
char	log_path_ismg_send[256];
char	log_path_ismg_recv[256];
char	log_path_db[256];

int main_init();
int main_run();
int move_log_file(time_t last);

int main(int argc, char *argv[])
{
	int		ret;

	ret = main_init();
	if(ret != 0){
		return ret;
	}

	ret = main_run();
	if(ret != 0){
		return ret;
	}
	return ret;
}

int main_init()
{
	char    fifo_path_ismg_send[256];
	char	fifo_path_ismg_recv[256];
	char	fifo_path_db[256];

	lg_home = getenv("CMPP_PROXY_HOME");
	if(lg_home == NULL){
		printf("getenv CMPP_PROXY_HOME failed\n");
		return EINVAL;
	}
	sprintf(fifo_path_ismg_send, "%s/%s", lg_home, LOG_FIFO_ISMG_SEND);
	sprintf(fifo_path_ismg_recv, "%s/%s", lg_home, LOG_FIFO_ISMG_RECV);
	sprintf(fifo_path_db, "%s/%s", lg_home, LOG_FIFO_DB);

	sprintf(log_path_ismg_send, "%s/%s", lg_home, LOG_FILE_ISMG_SEND);
	sprintf(log_path_ismg_recv, "%s/%s", lg_home, LOG_FILE_ISMG_RECV);
	sprintf(log_path_db, "%s/%s", lg_home, LOG_FILE_DB);

	printf("ismgsend.log:%s\n", log_path_ismg_send);
	printf("ismgrecv.log:%s\n", log_path_ismg_recv);
	printf("db.log:%s\n", log_path_db);

	printf("log system enter detach mode\n");
	process_detach();

fifoismgsend:
	fifo_fd_ismg_send = open(fifo_path_ismg_send, O_RDONLY | O_NONBLOCK, 0600);
	if(fifo_fd_ismg_send == -1){
		mkfifo(fifo_path_ismg_send, 0600);
		goto fifoismgsend;
	}
fifoismgrecv:
	fifo_fd_ismg_recv = open(fifo_path_ismg_recv, O_RDONLY | O_NONBLOCK, 0600);
	if(fifo_fd_ismg_recv == -1){
		mkfifo(fifo_path_ismg_recv, 0600);
		goto fifoismgrecv;
	}
fifodb:
	fifo_fd_db = open(fifo_path_db, O_RDONLY | O_NONBLOCK, 0600);
	if(fifo_fd_db == -1){
		mkfifo(fifo_path_db, 0600);
		goto fifodb;
	}
	log_fd_ismg_send = open(log_path_ismg_send, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK, 0600);
	if(log_fd_ismg_send == -1){
		printf("open ismgsend.log failed,%d\n", errno);
		return errno;
	}
	log_fd_ismg_recv = open(log_path_ismg_recv, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK, 0600);
	if(log_fd_ismg_recv == -1){
		printf("open ismgrecv.log failed,%d\n", errno);
		return errno;
	}
	log_fd_db = open(log_path_db, O_WRONLY | O_APPEND | O_CREAT | O_NONBLOCK, 0600);
	if(log_fd_db == -1){
		printf("open db.log failed,%d\n", errno);
		return errno;
	}
	return 0;
}

int main_run()
{
	int		nfds, i, day_last, day_cur;
	struct	pollfd	pfds[3];
	char	buf[PIPE_BUF];
	ssize_t	len;
	time_t	last, cur;
	struct	tm	tms;
	uint	num = 0;

	last = time(NULL);
	localtime_r(&last, &tms);
	day_last = tms.tm_yday;

	pfds[0].fd = fifo_fd_ismg_send;
	pfds[0].events = POLLIN;	
	pfds[1].fd = fifo_fd_ismg_recv;
	pfds[1].events = POLLIN;	
	pfds[2].fd = fifo_fd_db;
	pfds[2].events = POLLIN;	
	while(1){
		nfds = poll(pfds, 3, 10000);
		if(nfds < 0 && errno == EINTR)
			continue;
		if(nfds == 0)
			goto timeout;
		if(pfds[0].revents && POLLIN){
			i = 0;
			while(i++ < 10){
				memset(buf, 0, PIPE_BUF);
				len = read(fifo_fd_ismg_send, buf, PIPE_BUF);
				if(len == -1){
					break;
				}else{
					write(log_fd_ismg_send, buf, len);
				}
			}
		}
		if(pfds[1].revents && POLLIN){
			i = 0;
			while(i++ < 10){
				memset(buf, 0, PIPE_BUF);
				len = read(fifo_fd_ismg_recv, buf, PIPE_BUF);
				if(len == -1){
					break;
				}else{
					write(log_fd_ismg_recv, buf, len);
				}
			}
		}
		if(pfds[2].revents && POLLIN){
			i = 0;
			while(i++ < 10){
				memset(buf, 0, PIPE_BUF);
				len = read(fifo_fd_db, buf, PIPE_BUF);
				if(len == -1){
					break;
				}else{
					write(log_fd_db, buf, len);
				}
			}
		}
timeout:
		if(++num % 60 == 0){
			cur = time(NULL);
			localtime_r(&cur, &tms);
			day_cur = tms.tm_yday;
			if((day_cur > day_last) || (day_cur==0 && day_last==364) || (day_cur==0 && day_last==365)){
				move_log_file(last);
				day_last = day_cur;
				last = cur;
			}
		}
	}
	close(fifo_fd_ismg_send);
	close(fifo_fd_ismg_recv);
	close(fifo_fd_db);
	close(log_fd_ismg_send);
	close(log_fd_ismg_recv);
	close(log_fd_db);
	return 0;
}

int move_log_file(time_t last)
{
	int		ret;
	char	path[256];
	struct  tm tm;

	close(log_fd_ismg_send);
	close(log_fd_ismg_recv);
	close(log_fd_db);

	localtime_r(&last, &tm);

	sprintf(path, "%s/log/ismgsend_%04d%02d%02d.log", lg_home, tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday);
	ret = rename(log_path_ismg_send, path);
	if(ret != 0){
		return errno;
	}
	sprintf(path, "%s/log/ismgrecv_%04d%02d%02d.log", lg_home, tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday);
	ret = rename(log_path_ismg_recv, path);
	if(ret != 0){
		return errno;
	}
	sprintf(path, "%s/log/db_%04d%02d%02d.log", lg_home, tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday);
	ret = rename(log_path_db, path);
	if(ret != 0){
		return errno;
	}

	log_fd_ismg_send = open(log_path_ismg_send, O_WRONLY | O_CREAT | O_NONBLOCK, 0600);
	if(log_fd_ismg_send == -1){
		return errno;
	}
	log_fd_ismg_recv = open(log_path_ismg_recv, O_WRONLY | O_CREAT | O_NONBLOCK, 0600);
	if(log_fd_ismg_recv == -1){
		return errno;
	}
	log_fd_db = open(log_path_db, O_WRONLY | O_CREAT | O_NONBLOCK, 0600);
	if(log_fd_db == -1){
		return errno;
	}
	return 0;
}
