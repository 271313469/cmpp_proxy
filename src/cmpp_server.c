#include "cmpp_common.h"
#include "proxy.h"
#include "glo.h"

rsmg_node	*lg_rsmg = NULL;
int	lg_mqid_submit = -1;

static uint get_seq();
static int login_success(trans_t *trans);
static int recv_connect(trans_t *trans, cmpp_packet *pk);
static int recv_fwd(trans_t *trans, cmpp_packet *pk);
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
	trans->status = 1;
	trans->timeout = lg_rsmg->desc.timeout;
	trans->times = lg_rsmg->desc.times;

	lg_mqid_submit = msgget(G_MQID_SUBMIT + atoi(lg_rsmg->desc.rsmg_id), IPC_CREAT | 0600);
	if(lg_mqid_submit == -1){
		log_error(msgget, errno);
		return errno;
	}
	return 0;
}

static int recv_connect(trans_t *trans, cmpp_packet *pk)
{
	int		ret, i;
	cmpp_connect	*connect = &pk->body.connect;
	cmpp_connect_resp	*resp = &pk->body.connect_resp;
	char    auth[CMPP_PROTO_ATUH + 1];

	for(i=0; i<g_ismg_node->desc.max_rsmg; i++){
		if(g_rsmg_node[i] == NULL)
			continue;
		if(!strcmp(g_rsmg_node[i]->desc.rsmg_id, connect->source))
			break;
	}
	if(i >= g_ismg_node->desc.max_rsmg){
		log_printf("[recv_connect]:rsmg_id[%s]connect failed", connect->source);
		pk->header.cmd = CMPP_CMD_CONNECT_RESP;
		resp->status = 2;
		memset(resp->auth, 0, sizeof(resp->auth));
		resp->version = 0x20;
	}else{
		log_printf("[recv_connect]:rsmg_id[%s]connect ok", connect->source);
		pk->header.cmd = CMPP_CMD_CONNECT_RESP;
		strcpy(auth, connect->auth);
		resp->status = 0;
		strcpy(resp->auth, auth);
		resp->version = 0x20;
		//set login info
		lg_rsmg = g_rsmg_node[i];
		ret = login_success(trans);
		if(ret != 0){
			log_error(login_success, ret);
			return ret;
		}
	}
	ret = cmpp_send_packet(trans->connfd, pk);
	if(ret != 0){
		log_error(cmpp_send_packet, ret);
		return ret;
	}
	return 0;
}

static int recv_fwd(trans_t *trans, cmpp_packet *pk)
{
	int			ret;
	cmpp_msgbuf	msg;
	cmpp_packet	resp;

	//1.put mq
	if(pk->body.fwd.msg_fwd_type <= 1){
		msg.mtype = CMPP_CMD_FWD;
		memcpy(msg.mtext, pk, sizeof(cmpp_msgbuf)-sizeof(long));
		ret = msgsnd(lg_mqid_submit, &msg, sizeof(cmpp_msgbuf)-sizeof(long), 0);
		if(ret < 0){
			log_error(msgsnd, errno);
			return ret;
		}
	}
	//2.send resp
	memset(&resp, 0, sizeof(cmpp_packet));
	resp.header.cmd = CMPP_CMD_FWD_RESP;
	resp.header.seq = pk->header.seq;
	resp.body.fwd_resp.msg_id = pk->body.fwd.msg_id;
	resp.body.fwd_resp.pk_total = pk->body.fwd.pk_total;
	resp.body.fwd_resp.pk_number = pk->body.fwd.pk_number;
	resp.body.fwd_resp.result = 0;
	ret = cmpp_send_packet(trans->connfd, &resp);
	if(ret != 0){
		log_error(cmpp_send_packet, ret);
		return ret;
	}
	log_printf("[recv_fwd]:recv fwd[%llu]", ++lg_rsmg->flow.mt_ok);
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

	if(trans->status == 0){
		if(pk->header.cmd != CMPP_CMD_CONNECT){
			log_printf("[recv_packet]:rsmg unlogin");
			return 0;
		}
	}
	switch(pk->header.cmd){
		case CMPP_CMD_CONNECT:
			ret = recv_connect(trans, pk);
			break;
		case CMPP_CMD_FWD:
			ret = recv_fwd(trans, pk);
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

/* 1.handle timeout */
int cmpp_server_handle_timeout(trans_t *trans)
{
	int		ret;
	cmpp_packet	pk;

	if(trans->curtimes >= trans->times)
		return COM_ETIMEOUT;
	//send active
	if((time(NULL) - trans->last) > (trans->timeout * (1 + trans->curtimes))){
		pk.header.cmd = CMPP_CMD_ACTIVE_TEST;
		pk.header.seq = get_seq();
		ret = cmpp_send_packet(trans->connfd, &pk);
		if(ret != 0){
			log_error(cmpp_send_packet, ret);
			return ret;
		}
		trans->curtimes++;
		log_printf("[server_timeout]:send active,seq[%u]", pk.header.seq);
	}
	return 0;
}

/* 2.handle recv packet */
int cmpp_server_handle_recv(trans_t *trans)
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
