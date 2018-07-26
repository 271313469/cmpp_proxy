#include "common.h"
#include "glo.h"
#include <mysql/mysql.h>

int		lg_mode;
char	lg_home[256];

int main_init();
int main_run();
int child_main(int pfd, int connfd);
int child_handle_mt(int pfd);
int child_handle_mo(int pfd);
int handle_mt(MYSQL *conn, int mqid[]);
int handle_mo(MYSQL *conn, int mqid[]);

int main(int argc, char **argv)
{
	int		ret, c;

	if(argc != 2){
		printf("usage:db_proxy [-a] | [-b] | [-c]\n");
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
			printf("usage:db_proxy [-a] | [-b] | [-c]\n");
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
	char	*buf, path[256];

	buf = getenv("CMPP_PROXY_HOME");
	if(buf == NULL){
		printf("getenv CMPP_PROXY_HOME failed\n");
		return EINVAL;
	}
	strcpy(lg_home, buf);
	if(lg_mode == 1){
		ret = log_init(LOG_FILETYPE_NONE, path);
	}else if(lg_mode == 2){
		sprintf(path, "%s/%s", lg_home, LOG_FILE_DB);
		ret = log_init(LOG_FILETYPE_REGULAR, path);
	}else if(lg_mode == 3){
		sprintf(path, "%s/%s", lg_home, LOG_FIFO_DB);
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

	sprintf(path, "%s/%s", lg_home, CONF_PATH_DB);
	ret = read_db_conf(path);
	if(ret != 0){
		log_error(read_db_conf, ret);
		return ret;
	}
	return 0;
}

int main_run()
{
	int			pfd[2];
	pid_t		pid, pid_mo, pid_mt;

	if(socketpair(AF_UNIX, SOCK_STREAM, 0, pfd) < 0)
		return errno;

	pid_mo = fork();
	if(pid_mo < 0) {
		log_error(fork, errno);
		return errno;
	} else if(pid_mo == 0) {
		close(pfd[1]); //close write
		child_handle_mo(pfd[0]);
		exit(0);
	}

	pid_mt = fork();
	if(pid_mt < 0) {
		log_error(fork, errno);
		return errno;
	} else if(pid_mt == 0) {
		close(pfd[1]); //close write
		child_handle_mt(pfd[0]);
		exit(0);
	}

	close(pfd[0]);
	pid = wait(NULL);
	close(pfd[1]);
	pid = wait(NULL);
	return 0;
}

int handle_mo(MYSQL *conn, int mqid[])
{
	static ullong	count = 0;
	int         ret, i;
	MYSQL_RES   *res;
	MYSQL_ROW   row;
	ullong		num_rows;
	char        sql[256];
	cmpp_packet	pk;
	cmpp_msgbuf	msgbuf;
	char        content[160];
	char        *tok;
	cmpp_report report;

	sprintf(sql, "select * from t_mo_q limit %d", g_db_node->desc.limit);
	ret = mysql_query(conn, sql);
	if(ret != 0){
		log_error(mysql_query, ret);
		return ret;
	}
	res = mysql_store_result(conn);
	if(res == NULL){
		log_error(mysql_store_result, ret);
		return -1;
	}
	num_rows = mysql_num_rows(res);
	if(num_rows == 0){
		//log_printf("[handle_mo]:[t_mo_q] is empty");
		mysql_free_result(res);
		return 0;
	}
	while(num_rows--){
		row = mysql_fetch_row(res);
		if(row == NULL)
			break;
		//1.set pk
		memset(&pk, 0, sizeof(cmpp_packet));
		pk.header.cmd = CMPP_CMD_FWD;
		strcpy(pk.body.fwd.source_id, row[0]);
		strcpy(pk.body.fwd.destination_id, row[1]);
		pk.body.fwd.nodescount = atoi(row[2]);
		pk.body.fwd.msg_fwd_type = atoi(row[3]);
		pk.body.fwd.msg_id = atoll(row[4]);
		pk.body.fwd.pk_total = atoi(row[5]);
		pk.body.fwd.pk_number = atoi(row[6]);
		pk.body.fwd.reg_delivery = atoi(row[7]);
		pk.body.fwd.msg_level = atoi(row[8]);
		strcpy(pk.body.fwd.service_id, row[9]);
		pk.body.fwd.fee_usertype = atoi(row[10]);
		strcpy(pk.body.fwd.fee_terminal_id , row[11]);
		pk.body.fwd.tp_pid = atoi(row[12]);
		pk.body.fwd.tp_udhi = atoi(row[13]);
		pk.body.fwd.msg_fmt = atoi(row[14]);
		strcpy(pk.body.fwd.msg_src, row[15]);
		strcpy(pk.body.fwd.feetype, row[16]);
		strcpy(pk.body.fwd.feecode, row[17]);
		strcpy(pk.body.fwd.valid_time, row[18]);
		strcpy(pk.body.fwd.at_time, row[19]);
		strcpy(pk.body.fwd.src_id, row[20]);
		pk.body.fwd.destusr_tl = atoi(row[21]);
		strcpy(pk.body.fwd.dest_id[0], row[22]);
		pk.body.fwd.msg_length = atoi(row[23]);
		if(pk.body.fwd.msg_fwd_type <= 1){
			memcpy(pk.body.fwd.msg_content, row[24], pk.body.fwd.msg_length);
		}else{
			memset(&report, 0, sizeof(cmpp_report));
			strcpy(content, row[24]);
			tok = strtok(content, " "); if(tok != NULL) report.msg_id = atoll(tok);
            tok = strtok(NULL, " "); if(tok != NULL) strcpy(report.stat, tok);
            tok = strtok(NULL, " "); if(tok != NULL) strcpy(report.submit_time, tok);
            tok = strtok(NULL, " "); if(tok != NULL) strcpy(report.done_time, tok);
            tok = strtok(NULL, " "); if(tok != NULL) strcpy(report.dest_id, tok);
            tok = strtok(NULL, " "); if(tok != NULL) report.smsc_seq = atol(tok);
			memcpy(pk.body.fwd.msg_content, &report, sizeof(cmpp_report));
		}
		cmpp_print_pk(&pk);
		//2.set msgbuf
		memset(&msgbuf, 0, sizeof(cmpp_msgbuf));
		msgbuf.mtype = CMPP_CMD_FWD;
		memcpy(msgbuf.mtext, &pk, sizeof(cmpp_packet));
		//3.route
		for(i=0; i<g_ismg_node->desc.max_rsmg; i++){
			if(g_rsmg_node[i] == NULL)
				continue;
			if(!strcmp(g_rsmg_node[i]->desc.rsmg_id, pk.body.fwd.destination_id))
				break;
		}
		if(i >= g_ismg_node->desc.max_rsmg){
			log_printf("[handle_mo]:not match rsmg[%s]", pk.body.fwd.destination_id);
			continue;
		}
		//4.send msg
		ret = msgsnd(mqid[i], &msgbuf, sizeof(cmpp_msgbuf)-sizeof(long), 0);
		if(ret < 0){
			log_error(msgsnd, errno);
		}
		//5.delete
		sprintf(sql, "delete from t_mo_q where Msg_id=%llu", pk.body.fwd.msg_id);
		ret = mysql_query(conn, sql);
		if(ret != 0){
			log_error(mysql_query, ret);
		}
		log_printf("[handle_mo]:select mo count[%llu]", ++count);
	}
	mysql_free_result(res);
	return 0;
}
int handle_mt(MYSQL *conn, int mqid[])
{
	static ullong	count = 0;
	int         ret, i, len;
	char        sql[256], *end;
	cmpp_msgbuf msgbuf;
	cmpp_packet	pk;

	for(i=0; i<g_ismg_node->desc.max_rsmg; i++){
		if(g_rsmg_node[i] == NULL)
			continue;
		while(1){
			//1.recv msg
			len = msgrcv(mqid[i], &msgbuf, sizeof(cmpp_msgbuf)-sizeof(long), 0, IPC_NOWAIT);
			if(len < 0){
				if(errno == ENOMSG){
					//log_printf("[handle_mt]:[%s] is empty", g_rsmg_node[i]->desc.rsmg_id);
					break;
				}
				log_error(msgrcv, errno);
				break;
			}
			memcpy(&pk, msgbuf.mtext, sizeof(cmpp_packet));
			cmpp_print_pk(&pk);
			//2.insert database
			sprintf(sql, "insert into t_mt_q values('%s','%s',%u,%u,%llu,%u,%u,%u,%u,'%s',%u,'%s',%u,%u,%u,'%s','%s','%s','%s','%s','%s',%u,'%s',%u,",
        			pk.body.fwd.source_id, pk.body.fwd.destination_id, pk.body.fwd.nodescount, pk.body.fwd.msg_fwd_type,
					pk.body.fwd.msg_id, pk.body.fwd.pk_total, pk.body.fwd.pk_number, pk.body.fwd.reg_delivery, pk.body.fwd.msg_level,
					pk.body.fwd.service_id, pk.body.fwd.fee_usertype, pk.body.fwd.fee_terminal_id, pk.body.fwd.tp_pid, pk.body.fwd.tp_udhi,
					pk.body.fwd.msg_fmt, pk.body.fwd.msg_src, pk.body.fwd.feetype, pk.body.fwd.feecode, pk.body.fwd.valid_time,
					pk.body.fwd.at_time, pk.body.fwd.src_id, pk.body.fwd.destusr_tl, pk.body.fwd.dest_id[0], pk.body.fwd.msg_length);
			end = sql + strlen(sql);
			*end++ = '\'';
			end += mysql_real_escape_string(conn, end, pk.body.fwd.msg_content, pk.body.fwd.msg_length);
			*end++ = '\'';
			sprintf(end, ",'')");
			end += 4;

			ret = mysql_real_query(conn, sql, (unsigned int)(end - sql));
			if(ret != 0){
				log_error(mysql_real_query, ret);
			}
			log_printf("[handle_mt]:insert mt count[%llu]", ++count);
		}
	}
	return 0;
}
int child_handle_mo(int pfd)
{
	int		ret, i, nfds;
	struct	pollfd	pfds[1];
	MYSQL	*conn;
	int		mqid[G_RSMG_NUM_MAX];

	conn = mysql_init(NULL);
	if(conn == NULL){
		log_error(mysql_init, EINVAL);
		return EINVAL;
	}
	conn = mysql_real_connect(conn, g_db_node->desc.ip, g_db_node->desc.user, g_db_node->desc.pwd, g_db_node->desc.database, g_db_node->desc.port, NULL, 0);
	if(conn == NULL){
		log_error(mysql_real_connect, EINVAL);
		return errno;
	}
	//mysql_query(conn, "set names utf8;");

	for(i=0; i<g_ismg_node->desc.max_rsmg; i++){
		if(g_rsmg_node[i] == NULL)
			continue;
		mqid[i] = msgget(G_MQID_DELIVER + atoi(g_rsmg_node[i]->desc.rsmg_id), IPC_CREAT | 0600);
		if(mqid[i] < 0){
			log_error(msgget, errno);
			return errno;
		}
		log_printf("[child_handle_mo]:mqid[%d]=%d", i, mqid[i]);
	}

	pfds[0].fd = pfd;
	pfds[0].events = POLLIN;
	while(1){
		nfds = poll(pfds, 2, 1000 * g_db_node->desc.interval);
		if(nfds < 0 && errno == EINTR)
			continue;
		if(nfds == 0){
			ret = handle_mo(conn, mqid);
			if(ret != 0){
				log_error(handle_mo, ret);
				break;
			}
		}
		if(pfds[0].revents && POLLIN){
			log_printf("[child_handle_mo]:recv fath signal exit");
			break;
		}
	}
	close(pfd);
	log_printf("child_handle_mo exit");
	return 0;
}
int child_handle_mt(int pfd)
{
	int		ret, i, nfds;
	struct	pollfd	pfds[1];
	MYSQL	*conn;
	int		mqid[G_RSMG_NUM_MAX];

	conn = mysql_init(NULL);
	if(conn == NULL){
		log_error(mysql_init, EINVAL);
		return EINVAL;
	}
	conn = mysql_real_connect(conn, g_db_node->desc.ip, g_db_node->desc.user, g_db_node->desc.pwd, g_db_node->desc.database, g_db_node->desc.port, NULL, 0);
	if(conn == NULL){
		log_error(mysql_real_connect, EINVAL);
		return errno;
	}
	//mysql_query(conn, "set names utf8;");

	for(i=0; i<g_ismg_node->desc.max_rsmg; i++){
		if(g_rsmg_node[i] == NULL)
			continue;
		mqid[i] = msgget(G_MQID_SUBMIT + atoi(g_rsmg_node[i]->desc.rsmg_id), IPC_CREAT | 0600);
		if(mqid[i] < 0){
			log_error(msgget, errno);
			return errno;
		}
		log_printf("[child_handle_mt]:mqid[%d]=%d", i, mqid[i]);
	}

	pfds[0].fd = pfd;
	pfds[0].events = POLLIN;
	while(1){
		nfds = poll(pfds, 2, 1000 * g_db_node->desc.interval);
		if(nfds < 0 && errno == EINTR)
			continue;
		if(nfds == 0){
			ret = handle_mt(conn, mqid);
			if(ret != 0){
				log_error(handle_mt, ret);
				break;
			}
		}
		if(pfds[0].revents && POLLIN){
			log_printf("[child_handle_mt]:recv fath signal exit");
			break;
		}
	}
	close(pfd);
	log_printf("child_handle_mt exit");
	return 0;
}
