#include "cmpp_common.h"
#include "proxy.h"
#include "glo.h"

int		lg_mode;
char	*lg_home;

int main_init();
int main_run();
int child_main(int pfd, int connfd);
int retrans_main(int pfd);
int retrans_handle(int mqid_retrans, int mqid_deliver[]);
int ismg_send_main(int pfd, rsmg_node *rsmg);
int ismg_recv_main(int pfd, int connfd);

int main(int argc, char **argv)
{
	int		ret, c;

	if(argc != 2){
		printf("usage:ismg_proxy [-a] | [-b] | [-c]\n");
		printf("note:\t-a : print to console\n");
		printf("\t-b : print to ismg.log, for singal process\n");
		printf("\t-c : print to ismg.fifo, then to ismg.log, for multi process\n");
		exit(0);
	}
	c = getopt(argc, argv, "abc");
	switch(c){
		case 'a':
			lg_mode = 1;
			break;
		case 'b':
			lg_mode = 2;
			break;
		case 'c':
			lg_mode = 3;
			break;
		default:
			printf("usage:ismg_proxy [-a] | [-b] | [-c]\n");
			exit(0);
	}

	if(lg_mode != 1){
		printf("system enter detach mode\n");
		process_detach();
	}

	ret = main_init();
	if(ret != 0){
		log_error(main_init, ret);
		return ret;
	}

	ret = main_run();
	if(ret != 0){
		log_error(main_run, ret);
		return ret;
	}
	return ret;
}

int main_init()
{
	int		ret;
	char	path[256];

	lg_home = getenv("CMPP_PROXY_HOME");
	if(lg_home == NULL){
		log_error(getenv, EINVAL);
		return EINVAL;
	}

	if(lg_mode == 1){
		ret = log_init(LOG_FILETYPE_NONE, path);
	}else if(lg_mode == 2){
		sprintf(path, "%s/%s", lg_home, LOG_FILE_ISMG_RECV);
		ret = log_init(LOG_FILETYPE_REGULAR, path);
	}else if(lg_mode == 3){
		sprintf(path, "%s/%s", lg_home, LOG_FIFO_ISMG_RECV);
		ret = log_init(LOG_FILETYPE_FIFO, path);
	}
	if(ret != 0){
		printf("log_init failed,%d\n", ret);
		return ret;
	}

	sprintf(path, "%s/%s", lg_home, CONF_PATH_ISMG);
	ret = read_ismg_conf(path);
	if(ret != 0){
		log_error(read_ismg_conf, ret);
		return ret;
	}

	sprintf(path, "%s/%s", lg_home, CONF_PATH_RSMG);
	ret = read_rsmg_conf(path);
	if(ret != 0){
		log_error(read_rsmg_conf, ret);
		return ret;
	}
	return 0;
}

static void sig_chld(int signo)
{
	pid_t   pid;
	pid = wait(NULL);
	log_printf("[main]:child[%d]exit\n", pid);
}

int main_run()
{
	int			ret, listenfd, connfd, pfd[2], i, j;
	pid_t		pid;
	socklen_t	clilen;
	struct	sockaddr_in	cliaddr;

	signal(SIGCHLD, sig_chld);

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, pfd) < 0)
		return errno;

	/* 1.retrans process */
	pid = fork();
	if(pid == 0) {
		close(pfd[1]);
		retrans_main(pfd[0]);
		exit(0);
	}

	/* 2.ismg send process */
	for(i=0; i<g_ismg_node->desc.max_rsmg; i++){
		if(g_rsmg_node[i] == NULL)
			continue;
		for(j=0; j<g_rsmg_node[i]->desc.send_links; j++){
			pid = fork();
			if(pid == 0) {
				close(pfd[1]);
				ismg_send_main(pfd[0], g_rsmg_node[i]);
				exit(0);
			}
		}
	}

	/* 3.ismg recv process */
	ret = com_socket_create_tcp_listen(&listenfd, g_ismg_node->desc.ip, g_ismg_node->desc.port, 10);
	if(ret != 0){
		log_error(com_socket_create_tcp_listen, ret);
		return ret;
	}
	while(1){
		clilen = sizeof(cliaddr);
		connfd = accept(listenfd, (struct sockaddr *) &cliaddr, &clilen);
		if(connfd < 0) {
			if(errno == EINTR)
				continue;
			log_error(accept, errno);
			continue;
		}
		log_printf("[main]:accept new connect[%s]", inet_ntoa(cliaddr.sin_addr));
		pid = fork();
		if(pid == 0) {
			close(listenfd);
			close(pfd[1]);
			ismg_recv_main(pfd[0], connfd);
			exit(0);
		}
		close(connfd);
	}
	close(pfd[1]);
	return 0;
}

/* send child process */
int ismg_send_main(int pfd, rsmg_node *rsmg)
{
	int		ret, nfds;
	struct	pollfd	pfds[2];
	trans_t	trans;
	char	path[256];

	if(lg_mode == 1){
		ret = log_init(LOG_FILETYPE_NONE, path);
	}else if(lg_mode == 2){
		sprintf(path, "%s/%s", lg_home, LOG_FILE_ISMG_SEND);
		ret = log_init(LOG_FILETYPE_REGULAR, path);
	}else if(lg_mode == 3){
		sprintf(path, "%s/%s", lg_home, LOG_FIFO_ISMG_SEND);
		ret = log_init(LOG_FILETYPE_FIFO, path);
	}

	log_printf("[ismg_send_main]:start");
	pfds[0].fd = pfd;
	pfds[0].events = POLLIN;

reconn:
	log_printf("[ismg_send_main]:prepare connect rsmg[%s]", rsmg->desc.rsmg_id);
	trans_init(&trans);
	ret = cmpp_client_handle_login(&trans, rsmg);
	if(ret != 0){
		log_printf("[ismg_send_main]:connect failed rsmg[%s]", rsmg->desc.rsmg_id);
		nfds = poll(pfds, 1, trans.timeout);
		if(nfds > 0 && (pfds[0].revents && POLLIN)){
			log_printf("[ismg_send_main]:recv father exit signal");
			goto over;
		}
		goto reconn;
	}
	log_printf("[ismg_send_main]:connect ok rsmg[%s]", rsmg->desc.rsmg_id);

	pfds[1].fd = trans.connfd;
	pfds[1].events = POLLIN;
	while(1){
		nfds = poll(pfds, 2, 1000);
		if(nfds < 0 && errno == EINTR)
			continue;
		if(nfds == 0){
			ret = cmpp_client_handle_timeout(&trans);
			if(ret != 0){
				log_error(cmpp_client_handle_timeout, ret);
				break;
			}
		}else{
			if(pfds[0].revents && POLLIN){
				log_printf("[ismg_send_main]:recv father exit signal");
				goto over;
			}
			if(pfds[1].revents && POLLIN){
				ret = cmpp_client_handle_recv(&trans);
				if(ret != 0){
					log_error(cmpp_client_handle_recv, ret);
					break;
				}
			}
		}
		ret = cmpp_client_handle_send(&trans);
		if(ret != 0){
			log_error(cmpp_client_handle_send, ret);
			break;
		}
	}
	trans_destroy(&trans);
	log_printf("[ismg_send_main]:disconnect rsmg[%s] ", rsmg->desc.rsmg_id);
	sleep(3);
	goto reconn;
over:
	close(pfd);
	log_printf("[ismg_send_main]:exit");
	return 0;
}

/* recv child process */
int ismg_recv_main(int pfd, int connfd)
{
	int		ret, nfds;
	struct	pollfd	pfds[2];
	trans_t	trans;

	log_printf("[ismg_recv_main]:start");
	trans_init(&trans);
	trans.connfd = connfd;

	pfds[0].fd = pfd;
	pfds[0].events = POLLIN;
	pfds[1].fd = connfd;
	pfds[1].events = POLLIN;
	while(1){
		nfds = poll(pfds, 2, 1000);
		if(nfds < 0 && errno == EINTR)
			continue;
		if(nfds == 0){
			ret = cmpp_server_handle_timeout(&trans);
			if(ret != 0){
				log_error(cmpp_server_handle_timeout, ret);
				break;
			}
		}else{
			if(pfds[0].revents && POLLIN){
				log_printf("[ismg_recv_main]:recv father exit signal");
				break;
			}
			if(pfds[1].revents && POLLIN){
				ret = cmpp_server_handle_recv(&trans);
				if(ret != 0){
					log_error(cmpp_server_handle_recv, ret);
					break;
				}
			}
		}
	}
	trans_destroy(&trans);
	close(pfd);
	log_printf("[ismg_recv_main]:exit");
	return 0;
}

/* retrans process */
int retrans_main(int pfd)
{
	int     ret, i, nfds;
	struct  pollfd  pfds[1];
	int		mqid_retrans, mqid_deliver[G_RSMG_NUM_MAX];

	log_printf("[retrans_main]:start");

	mqid_retrans = msgget(G_MQID_RETRANS, IPC_CREAT | 0600);
	if(mqid_retrans == -1){
		log_error(msgget, errno);
		return errno;
	}
	for(i=0; i<g_ismg_node->desc.max_rsmg; i++){
		if(g_rsmg_node[i] == NULL)
			continue;
		mqid_deliver[i] = msgget(G_MQID_DELIVER + atoi(g_rsmg_node[i]->desc.rsmg_id), IPC_CREAT | 0600);
		if(mqid_deliver[i] < 0){
			log_error(msgget, errno);
			return errno;
		}
	}

	pfds[0].fd = pfd;
	pfds[0].events = POLLIN;
	while(1){
		nfds = poll(pfds, 1, 60000);
		if(nfds < 0 && errno == EINTR)
			continue;
		if(nfds == 0){
			ret = retrans_handle(mqid_retrans, mqid_deliver);
			if(ret != 0){
				log_error(retrans_handle, ret);
				break;
			}
		}
		if(pfds[0].revents && POLLIN){
			log_printf("[retrna_main]:recv father exit signal");
			break;
		}
	}
	close(pfd);
	log_printf("[retrans_main]:exit");
	return 0;
}

int retrans_handle(int mqid_retrans, int mqid_deliver[])
{
	int		ret, i;
	ssize_t	size;
	cmpp_msgbuf	msgbuf;
	cmpp_packet	pk;

	while(1){
		//1.recv msg
		size = msgrcv(mqid_retrans, &msgbuf, sizeof(cmpp_msgbuf)-sizeof(long), 0, IPC_NOWAIT);
		if(size < 0){
			if(errno == ENOMSG){
			}else{
				log_error(msgrcv, errno);
			}
			break;
		}
		memcpy(&pk, msgbuf.mtext, sizeof(cmpp_packet));
		cmpp_print_pk(&pk);

		for(i=0; i<g_ismg_node->desc.max_rsmg; i++){
			if(g_rsmg_node[i] == NULL)
				continue;
			if(!strcmp(g_rsmg_node[i]->desc.rsmg_id, pk.body.fwd.destination_id))
				break;
		}
		if(i >= g_ismg_node->desc.max_rsmg){
			log_printf("[retrans_handle]:not match rsmg_id[%s]", pk.body.fwd.destination_id);
			continue;
		}
		log_printf("[retrnas_handle]:match rsmg_id[%s]", pk.body.fwd.destination_id);
		ret = msgsnd(mqid_deliver[i], &msgbuf, sizeof(cmpp_msgbuf)-sizeof(long), 0);
		if(ret < 0){
			log_error(msgsnd, errno);
		}
	}
	return 0;
}
