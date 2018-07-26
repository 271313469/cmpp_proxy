#include "cmpp_common.h"
#include "proxy.h"
#include "glo.h"
#include <openssl/md5.h>

static rsmg_node	*lg_rsmg = NULL;
static int	lg_mqid_deliver = -1;
static int	lg_mqid_retrans = -1;

static uint get_seq();
static int login_success(trans_t *trans);
static int recv_fwd_resp(trans_t *trans, cmpp_packet *pk);
static int recv_active(trans_t *trans, cmpp_packet *pk);
static int recv_active_resp(trans_t *trans, cmpp_packet *pk);
static int handle_recv_packet(trans_t *trans, cmpp_packet *pk);

static uint get_seq()
{
	static	uint lg_seq = 0;
	if(++lg_seq > 0x7fffffff)
		lg_seq = 1;
	return lg_seq;
}

static int login_success(trans_t *trans)
{
	int		ret;

	trans->status = 1;
	trans->timeout = lg_rsmg->desc.timeout;
	trans->times = lg_rsmg->desc.times;
	trans->window = lg_rsmg->desc.window;
	ret = cmpp_window_init(&trans->pwin, trans->window, trans->timeout);
	if(ret != 0){
		log_error(cmpp_window_init, ret);
		return ret;
	}

	lg_mqid_deliver = msgget(G_MQID_DELIVER + atoi(lg_rsmg->desc.rsmg_id), IPC_CREAT | 0600);
	if(lg_mqid_deliver == -1){
		log_error(msgget, errno);
		return errno;
	}
	lg_mqid_retrans = msgget(G_MQID_RETRANS, IPC_CREAT | 0600);
	if(lg_mqid_retrans == -1){
		log_error(msgget, errno);
		return errno;
	}
	return 0;
}

static int recv_fwd_resp(trans_t *trans, cmpp_packet *pk)
{
	int		ret;
	cmpp_packet	value;

	ret = cmpp_window_del(&trans->pwin, pk->header.seq, &value);
	if(ret != 0){
		log_error(cmpp_window_del, ret);
	}
	return 0;
}

static int recv_active(trans_t *trans, cmpp_packet *pk)
{
	int		ret;

	pk->header.cmd = CMPP_CMD_ACTIVE_TEST_RESP;
	ret = cmpp_send_packet(trans->connfd, pk);
	if(ret != 0){
		log_error(cmpp_send_packet, ret);
		return ret;
	}
	return 0;
}

static int recv_active_resp(trans_t *trans, cmpp_packet *pk)
{
	if(trans->curtimes > 0)
		trans->curtimes--;
	return 0;
}

static int handle_recv_packet(trans_t *trans, cmpp_packet *pk)
{
	int		ret = 0;

	switch(pk->header.cmd){
		case CMPP_CMD_FWD_RESP:
			ret = recv_fwd_resp(trans, pk);
			break;
		case CMPP_CMD_ACTIVE_TEST:
			ret = recv_active(trans, pk);
			break;
		case CMPP_CMD_ACTIVE_TEST_RESP:
			ret = recv_active_resp(trans, pk);
			break;
		default:
			return CMPP_STAT_SP_ECMD;
	}
	return ret;
}

/* 1.handle login */
int cmpp_client_handle_login(trans_t *trans, rsmg_node *rsmg)
{
	int		ret, sockfd;
	cmpp_packet	pk;
	char	timestamp[11], data[48], auth[17];
	time_t	now;
	struct	tm tm;
	
	ret = com_socket_create_tcp_connect(&sockfd, rsmg->desc.ip, rsmg->desc.port);
	if(ret != 0){
		return ret;
	}
	trans->connfd = sockfd;

	//make auth
	now = time(NULL);
	localtime_r(&now, &tm);
	sprintf(timestamp, "%02d%02d%02d%02d%02d", tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	memset(data, 0, sizeof(auth));
	sprintf(data, "%s", g_ismg_node->desc.ismg_id);
	sprintf(&data[15], "%s%s", rsmg->desc.send_pwd, timestamp);
	memset(auth, 0, sizeof(auth));
	MD5((const unsigned char *)data, 6+9+strlen(rsmg->desc.send_pwd)+10, (unsigned char *)auth);
	//make packet
	memset(&pk, 0, sizeof(cmpp_packet));
	pk.header.cmd = CMPP_CMD_CONNECT;
	pk.header.seq = get_seq();
	strcpy(pk.body.connect.source, g_ismg_node->desc.ismg_id);
	memcpy(pk.body.connect.auth, auth, CMPP_PROTO_ATUH);
	pk.body.connect.version = rsmg->desc.protocol;
	pk.body.connect.timestamp = atoi(timestamp);
	//send connect
	ret = cmpp_send_packet(trans->connfd, &pk);
	if(ret != 0){
		log_error(cmpp_send_packet, ret);
		return ret;
	}
	//recv resp
	ret = cmpp_recv_packet(trans->connfd, &pk);
	if(ret != 0){
		log_error(cmpp_recv_packet, ret);
		return ret;
	}
	cmpp_print_pk(&pk);
	if(pk.header.cmd == CMPP_CMD_CONNECT_RESP && pk.body.connect_resp.status == 0){
		lg_rsmg = rsmg;
		login_success(trans);
		return 0;
	}
	return COM_EFAIL;
}

/* 2.handle timeout */
int cmpp_client_handle_timeout(trans_t *trans)
{
	int		ret, times;
	cmpp_msgbuf	msg;
	cmpp_packet	pk;

	if(trans->curtimes >= trans->times)
		return COM_ETIMEOUT;
	//1.check window
	ret = cmpp_window_timeout(&trans->pwin, &pk);
	if(ret == 0){
		times = atoi(pk.body.fwd.reserve);
		if(times < trans->times){
			sprintf(pk.body.fwd.reserve, "%d", 1+times);
			msg.mtype = CMPP_CMD_FWD;
			memcpy(&msg.mtext, &pk, sizeof(cmpp_msgbuf)-sizeof(long));
			ret = msgsnd(lg_mqid_retrans, &msg, sizeof(cmpp_msgbuf)-sizeof(long), 0);
			if(ret < 0){
				log_error(msgsnd, errno);
			}
			log_printf("[client_timeout]:fwd[%llu]retrans", pk.body.fwd.msg_id);
		}else{
			log_printf("[client_timeout]:fwd[%llu]retrans over", pk.body.fwd.msg_id);
		}
	}
	//2.send active
	if((time(NULL) - trans->last) > (trans->timeout * (1 + trans->curtimes))){
		pk.header.cmd = CMPP_CMD_ACTIVE_TEST;
		pk.header.seq = get_seq();
		ret = cmpp_send_packet(trans->connfd, &pk);
		if(ret != 0){
			log_error(cmpp_send_packet, ret);
			return ret;
		}
		trans->curtimes++;
		log_printf("[client_timeout]:send active,seq[%u]", pk.header.seq);
	}
	return 0;
}

/* 3.handle send packet */
int cmpp_client_handle_send(trans_t *trans)
{
	int		ret;
	cmpp_msgbuf	msg;
	ssize_t	len;
	cmpp_packet	pk;
	uint	num = 0;

	if(trans->status == 0){
		log_printf("[client_send]:rsmg unlogin");
		return 0;
	}
	ret = cmpp_window_get_free(&trans->pwin, &num);
	if(ret != 0){
		log_error(cmpp_window_get_free, ret);
	}
	while(num-- > 0){
		//1.recv msg
		len = msgrcv(lg_mqid_deliver, &msg, sizeof(cmpp_msgbuf)-sizeof(long), 0, IPC_NOWAIT);
		if(len < 0){
			if(errno == ENOMSG){
				//log_printf("[client_send]:mq[%s]empty,window[%u]\n", lg_rsmg->desc.rsmg_id, num+1);
			}else{
				log_error(msgrcv, errno);
			}
			break;
		}
		memcpy(&pk, msg.mtext, len);
		//2.send msg
		pk.header.seq = get_seq();
		cmpp_print_pk(&pk);
		ret = cmpp_send_packet(trans->connfd, &pk);
		if(ret != 0){
			log_error(cmpp_send_packet, ret);
			return ret;
		}
		//3.inser window
		ret = cmpp_window_add(&trans->pwin, pk.header.seq, &pk);
		if(ret != 0){
			log_error(cmpp_window_add, ret);
		}
		if(pk.body.fwd.msg_fwd_type <= 1)
			log_printf("[client_send]:send fwd[%llu]", ++lg_rsmg->flow.mo_ok);
		else
			log_printf("[client_send]:send report[%llu]", ++lg_rsmg->flow.mtsr_ok);
	}
	return 0;
}

/* 4.handle recv packet */
int cmpp_client_handle_recv(trans_t *trans)
{
	int		ret;
	cmpp_packet	pk;

	memset(&pk, 0, sizeof(cmpp_packet));
	ret = cmpp_recv_packet(trans->connfd, &pk);
	if(ret != 0){
		log_error(cmpp_recv_packet, ret);
		return ret;
	}
	cmpp_print_pk(&pk);
	ret = handle_recv_packet(trans, &pk);
	if(ret != 0){
		log_error(handle_recv_packet, ret);
		return ret;
	}
	trans->last = time(NULL);
	return 0;
}
