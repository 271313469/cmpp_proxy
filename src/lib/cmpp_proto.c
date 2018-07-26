#include "cmpp_proto.h"

int parse_header(char buf[], size_t len, cmpp_packet *pk);
int parse_connect(char buf[], size_t len, cmpp_packet *pk);
int parse_connect_resp(char buf[], size_t len, cmpp_packet *pk);
int parse_submit(char buf[], size_t len, cmpp_packet *pk);
int parse_submit_resp(char buf[], size_t len, cmpp_packet *pk);
int parse_deliver(char buf[], size_t len, cmpp_packet *pk);
int parse_deliver_resp(char buf[], size_t len, cmpp_packet *pk);
int parse_fwd(char buf[], size_t len, cmpp_packet *pk);
int parse_fwd_resp(char buf[], size_t len, cmpp_packet *pk);

int make_header(cmpp_packet *pk, char buf[], size_t *len);
int make_connect(cmpp_packet *pk, char buf[], size_t *len);
int make_connect_resp(cmpp_packet *pk, char buf[], size_t *len);
int make_submit(cmpp_packet *pk, char buf[], size_t *len);
int make_submit_resp(cmpp_packet *pk, char buf[], size_t *len);
int make_deliver(cmpp_packet *pk, char buf[], size_t *len);
int make_deliver_resp(cmpp_packet *pk, char buf[], size_t *len);
int make_fwd(cmpp_packet *pk, char buf[], size_t *len);
int make_fwd_resp(cmpp_packet *pk, char buf[], size_t *len);

void print_header(cmpp_packet *pk);
void print_connect(cmpp_packet *pk);
void print_connect_resp(cmpp_packet *pk);
void print_submit(cmpp_packet *pk);
void print_submit_resp(cmpp_packet *pk);
void print_deliver(cmpp_packet *pk);
void print_deliver_resp(cmpp_packet *pk);
void print_active(cmpp_packet *pk);
void print_active_resp(cmpp_packet *pk);
void print_fwd(cmpp_packet *pk);
void print_fwd_resp(cmpp_packet *pk);

/*
 * interface functions
 */
int cmpp_parse_buf2pk(char buf[], size_t len, cmpp_packet *pk)
{
	int		ret = 0;

	if(buf == NULL || pk == NULL)
		return EINVAL;
	if(len < CMPP_PACKET_LEN_HEADER || len > CMPP_PACKET_LEN_MAX)
		return CMPP_STAT_SP_ELEN;
	memset(pk, 0, sizeof(cmpp_packet));
	ret = parse_header(buf, len, pk);
	if(ret != 0)
		return ret;
	switch(pk->header.cmd){
		case CMPP_CMD_CONNECT:
			ret = parse_connect(buf + CMPP_PACKET_LEN_HEADER, len - CMPP_PACKET_LEN_HEADER, pk);
			break;
		case CMPP_CMD_CONNECT_RESP:
			ret = parse_connect_resp(buf + CMPP_PACKET_LEN_HEADER, len - CMPP_PACKET_LEN_HEADER, pk);
			break;
		case CMPP_CMD_SUBMIT:
			ret = parse_submit(buf + CMPP_PACKET_LEN_HEADER, len - CMPP_PACKET_LEN_HEADER, pk);
			break;
		case CMPP_CMD_SUBMIT_RESP:
			ret = parse_submit_resp(buf + CMPP_PACKET_LEN_HEADER, len - CMPP_PACKET_LEN_HEADER, pk);
			break;
		case CMPP_CMD_DELIVER:
			ret = parse_deliver(buf + CMPP_PACKET_LEN_HEADER, len - CMPP_PACKET_LEN_HEADER, pk);
			break;
		case CMPP_CMD_DELIVER_RESP:
			ret = parse_deliver_resp(buf + CMPP_PACKET_LEN_HEADER, len - CMPP_PACKET_LEN_HEADER, pk);
			break;
		case CMPP_CMD_FWD:
			ret = parse_fwd(buf + CMPP_PACKET_LEN_HEADER, len - CMPP_PACKET_LEN_HEADER, pk);
			break;
		case CMPP_CMD_FWD_RESP:
			ret = parse_fwd_resp(buf + CMPP_PACKET_LEN_HEADER, len - CMPP_PACKET_LEN_HEADER, pk);
			break;
		case CMPP_CMD_ACTIVE_TEST:
			break;
		case CMPP_CMD_ACTIVE_TEST_RESP:
			break;
		default:
			ret = CMPP_STAT_SP_ECMD;
	}
	return ret;
}
int cmpp_make_pk2buf(cmpp_packet *pk, char buf[], size_t *len)
{
	int		ret = 0;
	size_t	nhead, n = 0;

	if(pk == NULL || buf == NULL || len == NULL)
		return EINVAL;

	switch(pk->header.cmd){
		case CMPP_CMD_CONNECT:
			ret = make_connect(pk, buf + CMPP_PACKET_LEN_HEADER, &n);
			break;
		case CMPP_CMD_CONNECT_RESP:
			ret = make_connect_resp(pk, buf + CMPP_PACKET_LEN_HEADER, &n);
			break;
		case CMPP_CMD_SUBMIT:
			ret = make_submit(pk, buf + CMPP_PACKET_LEN_HEADER, &n);
			break;
		case CMPP_CMD_SUBMIT_RESP:
			ret = make_submit_resp(pk, buf + CMPP_PACKET_LEN_HEADER, &n);
			break;
		case CMPP_CMD_DELIVER:
			ret = make_deliver(pk, buf + CMPP_PACKET_LEN_HEADER, &n);
			break;
		case CMPP_CMD_DELIVER_RESP:
			ret = make_deliver_resp(pk, buf + CMPP_PACKET_LEN_HEADER, &n);
			break;
		case CMPP_CMD_FWD:
			ret = make_fwd(pk, buf + CMPP_PACKET_LEN_HEADER, &n);
			break;
		case CMPP_CMD_FWD_RESP:
			ret = make_fwd_resp(pk, buf + CMPP_PACKET_LEN_HEADER, &n);
			break;
		case CMPP_CMD_ACTIVE_TEST:
			break;
		case CMPP_CMD_ACTIVE_TEST_RESP:
			buf[CMPP_PACKET_LEN_HEADER] = 0;
			n = 1;
			break;
		default:
			ret = CMPP_STAT_SP_ECMD;
	}
	*len = CMPP_PACKET_LEN_HEADER + n;
	pk->header.len = *len;
	make_header(pk, buf, &nhead);
	return ret;
}
void cmpp_print_pk(cmpp_packet *pk)
{
	if(pk == NULL)
		return;
	switch(pk->header.cmd){
		case CMPP_CMD_CONNECT:
			print_connect(pk);
			break;
		case CMPP_CMD_CONNECT_RESP:
			print_connect_resp(pk);
			break;
		case CMPP_CMD_SUBMIT:
			print_submit(pk);
			break;
		case CMPP_CMD_SUBMIT_RESP:
			print_submit_resp(pk);
			break;
		case CMPP_CMD_DELIVER:
			print_deliver(pk);
			break;
		case CMPP_CMD_DELIVER_RESP:
			print_deliver_resp(pk);
			break;
		case CMPP_CMD_ACTIVE_TEST:
			print_active(pk);
			break;
		case CMPP_CMD_ACTIVE_TEST_RESP:
			print_active_resp(pk);
			break;
		case CMPP_CMD_FWD:
			print_fwd(pk);
			break;
		case CMPP_CMD_FWD_RESP:
			print_fwd_resp(pk);
			break;
		default:
			print_header(pk);
			break;
	}   
}

/*
 * 1. parse pk
 */
int parse_header(char buf[], size_t len, cmpp_packet *pk)
{
	char	*p = buf;
	cmpp_header	*header = &pk->header;
	uint	net32;

	memcpy(&net32, p, 4);
	header->len = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	header->cmd = ntohl(net32);
	p += 4;

	memcpy(&net32, p, 4);
	header->seq = ntohl(net32);

	if(len < header->len)
		return CMPP_STAT_SP_ELEN;
	return 0;
}
int parse_connect(char buf[], size_t len, cmpp_packet *pk)
{
	char    *p = buf;
	cmpp_connect	*connect = &pk->body.connect;
	uint	net32;

	memcpy(&connect->source, p, CMPP_PROTO_SP_ID);
	p += CMPP_PROTO_SP_ID;

	memcpy(&connect->auth, p, CMPP_PROTO_ATUH);
	p += CMPP_PROTO_ATUH;

	connect->version = *p++;

	memcpy(&net32, p, 4);
	connect->timestamp = ntohl(net32);
	p += 4;

	if(len < p-buf)
		return CMPP_STAT_SP_ELEN;
	return 0;
}

int parse_connect_resp(char buf[], size_t len, cmpp_packet *pk)
{
	char    *p = buf;
	cmpp_connect_resp	*connect_resp = &pk->body.connect_resp;

	connect_resp->status = *p++;

	memcpy(&connect_resp->auth, p, CMPP_PROTO_ATUH);
	p += CMPP_PROTO_ATUH;

	connect_resp->version = *p++;

	if(len < p-buf)
		return CMPP_STAT_SP_ELEN;
	return 0;
}
int parse_submit(char buf[], size_t len, cmpp_packet *pk)
{
	char    *p = buf;
	cmpp_submit		*submit = &pk->body.submit;
	ullong	net64;

	memcpy(&net64, p, 8);
	submit->msg_id = be64toh(net64);
	p += 8;

	submit->pk_total = *p++;
	submit->pk_number = *p++;
	submit->reg_delivery = *p++;
	submit->msg_level = *p++;

	memcpy(&submit->service_id, p, CMPP_PROTO_SERVICE);
	p += CMPP_PROTO_SERVICE;

	submit->fee_usertype = *p++;

	memcpy(&submit->fee_terminal_id, p, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	submit->tp_pid = *p++;
	submit->tp_udhi = *p++;
	submit->msg_fmt = *p++;

	memcpy(&submit->msg_src, p, CMPP_PROTO_SP_ID);
	p += CMPP_PROTO_SP_ID;

	memcpy(&submit->feetype, p, CMPP_PROTO_FEETYPE);
	p += CMPP_PROTO_FEETYPE;

	memcpy(&submit->feecode, p, CMPP_PROTO_FEECODE);
	p += CMPP_PROTO_FEECODE;

	memcpy(&submit->valid_time, p, CMPP_PROTO_TIME);
	p += CMPP_PROTO_TIME;

	memcpy(&submit->at_time, p, CMPP_PROTO_TIME);
	p += CMPP_PROTO_TIME;

	memcpy(&submit->src_id, p, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	submit->destusr_tl = *p++;
	if(submit->destusr_tl > CMPP_PROTO_DESTUSERTL)
		return CMPP_STAT_SP_EDEST_ID;

	memcpy(&submit->dest_id[0], p, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	submit->msg_length = *p++;

	memcpy(&submit->msg_content, p, submit->msg_length);
	p += submit->msg_length;

	memcpy(&submit->reserve, p, CMPP_PROTO_RESERVE);
	p += CMPP_PROTO_RESERVE;

	if(len < p-buf)
		return CMPP_STAT_SP_ELEN;
	return 0;
}
int parse_submit_resp(char buf[], size_t len, cmpp_packet *pk)
{
	char    *p = buf;
	cmpp_submit_resp	*submit_resp = &pk->body.submit_resp;
	ullong	net64;

	memcpy(&net64, p, 8);
	submit_resp->msg_id = be64toh(net64);
	p += 8;

	submit_resp->result = *p++;

	if(len < p-buf)
		return CMPP_STAT_SP_ELEN;
	return 0;
}
int parse_deliver(char buf[], size_t len, cmpp_packet *pk)
{
	char    *p = buf;
	cmpp_deliver	*deliver = &pk->body.deliver;
	cmpp_report		report;
	ullong			net64;
	uint			net32;

	memcpy(&net64, p, 8);
	deliver->msg_id = be64toh(net64);
	p += 8;

	memcpy(&deliver->dest_id, p, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	memcpy(&deliver->service_id, p, CMPP_PROTO_SERVICE);
	p += CMPP_PROTO_SERVICE;

	deliver->tp_pid = *p++;
	deliver->tp_udhi = *p++;
	deliver->msg_fmt = *p++;

	memcpy(&deliver->src_id, p, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	deliver->reg_delivery = *p++; 
	deliver->msg_length = *p++;
	if(deliver->msg_length > CMPP_PROTO_CONTENT)
		return CMPP_STAT_SP_ELEN;

	if(deliver->reg_delivery == 0){
		memcpy(&deliver->msg_content, p, deliver->msg_length);
		p += deliver->msg_length;
	}else{
		memcpy(&net64, p, 8);
		report.msg_id = be64toh(net64);
		p += 8;

		memcpy(&report.stat, p, CMPP_PROTO_REPORT_STAT);
		p += CMPP_PROTO_REPORT_STAT;

		memcpy(&report.submit_time, p, CMPP_PROTO_REPORT_TIME);
		p += CMPP_PROTO_REPORT_TIME;

		memcpy(&report.done_time, p, CMPP_PROTO_REPORT_TIME);
		p += CMPP_PROTO_REPORT_TIME;

		memcpy(&report.dest_id, p, CMPP_PROTO_MSISDN);
		p += CMPP_PROTO_MSISDN;

		memcpy(&net32, p, 4);
		report.smsc_seq = ntohl(net32);
		p += 4;

		memcpy(&deliver->msg_content, &report, sizeof(cmpp_report));
	}

	memcpy(&deliver->reserve, p, CMPP_PROTO_RESERVE);
	p+= CMPP_PROTO_RESERVE;

	if(len < p-buf)
		return CMPP_STAT_SP_ELEN;
	return 0;
}
int parse_deliver_resp(char buf[], size_t len, cmpp_packet *pk)
{
	char    *p = buf;
	cmpp_deliver_resp	*deliver_resp = &pk->body.deliver_resp;
	ullong	net64;

	memcpy(&net64, p, 8);
	deliver_resp->msg_id = be64toh(net64);
	p += 8;

	deliver_resp->result = *p++;

	if(len < p-buf)
		return CMPP_STAT_SP_ELEN;
	return 0;
}
int parse_fwd(char buf[], size_t len, cmpp_packet *pk)
{
	char    *p = buf;
	cmpp_fwd	*fwd = &pk->body.fwd;
	ullong	net64;

	memcpy(&fwd->source_id, p, CMPP_PROTO_ISMG_ID);
	p += CMPP_PROTO_ISMG_ID;

	memcpy(&fwd->destination_id, p, CMPP_PROTO_ISMG_ID);
	p += CMPP_PROTO_ISMG_ID;

	fwd->nodescount = *p++;
	fwd->msg_fwd_type = *p++;

	memcpy(&net64, p, 8);
	fwd->msg_id = be64toh(net64);
	p += 8;

	fwd->pk_total = *p++;
	fwd->pk_number = *p++;
	fwd->reg_delivery = *p++;
	fwd->msg_level = *p++;

	memcpy(&fwd->service_id, p, CMPP_PROTO_SERVICE);
	p += CMPP_PROTO_SERVICE;

	fwd->fee_usertype = *p++;

	memcpy(&fwd->fee_terminal_id, p, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	fwd->tp_pid = *p++;
	fwd->tp_udhi = *p++;
	fwd->msg_fmt = *p++;

	memcpy(&fwd->msg_src, p, CMPP_PROTO_SP_ID);
	p += CMPP_PROTO_SP_ID;

	memcpy(&fwd->feetype, p, CMPP_PROTO_FEETYPE);
	p += CMPP_PROTO_FEETYPE;

	memcpy(&fwd->feecode, p, CMPP_PROTO_FEECODE);
	p += CMPP_PROTO_FEECODE;

	memcpy(&fwd->valid_time, p, CMPP_PROTO_TIME);
	p += CMPP_PROTO_TIME;

	memcpy(&fwd->at_time, p, CMPP_PROTO_TIME);
	p += CMPP_PROTO_TIME;

	memcpy(&fwd->src_id, p, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	fwd->destusr_tl = *p++;
	if(fwd->destusr_tl > CMPP_PROTO_DESTUSERTL)
		return CMPP_STAT_SP_EDEST_ID;

	memcpy(&fwd->dest_id[0], p, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	fwd->msg_length = *p++;

	memcpy(&fwd->msg_content, p, fwd->msg_length);
	p += fwd->msg_length;

	memcpy(&fwd->reserve, p, CMPP_PROTO_RESERVE);
	p += CMPP_PROTO_RESERVE;

	if(len < p-buf)
		return CMPP_STAT_SP_ELEN;
	return 0;
}
int parse_fwd_resp(char buf[], size_t len, cmpp_packet *pk)
{
	char    *p = buf;
	cmpp_fwd_resp	*fwd_resp = &pk->body.fwd_resp;
	ullong	net64;

	memcpy(&net64, p, 8);
	fwd_resp->msg_id = be64toh(net64);
	p += 8;

	fwd_resp->pk_total = *p++;
	fwd_resp->pk_number = *p++;
	fwd_resp->result = *p++;

	if(len < p-buf)
		return CMPP_STAT_SP_ELEN;
	return 0;
}

/*
 *	2. make pk
 */
int make_header(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_header	*header = &pk->header;
	uint	net32;

	net32 = htonl(header->len);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(header->cmd);
	memcpy(p, &net32, 4);
	p += 4;

	net32 = htonl(header->seq);
	memcpy(p, &net32, 4);
	p += 4;

	*len = p - buf;
	return 0;
}
int make_connect(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_connect	*connect = &pk->body.connect;
	uint	net32;

	memcpy(p, connect->source, CMPP_PROTO_SP_ID);
	p += CMPP_PROTO_SP_ID;

	memcpy(p, connect->auth, CMPP_PROTO_ATUH);
	p += CMPP_PROTO_ATUH;

	*p++ = connect->version;

	net32 = htonl(connect->timestamp);
	memcpy(p, &net32, 4);
	p += 4;

	*len = p - buf;
	return 0;
}
int make_connect_resp(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_connect_resp	*connect_resp = &pk->body.connect_resp;

	*p++ = connect_resp->status;

	memcpy(p, connect_resp->auth, CMPP_PROTO_ATUH);
	p += CMPP_PROTO_ATUH;

	*p++ = connect_resp->version;

	*len = p - buf;
	return 0;
}
int make_submit(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_submit		*submit = &pk->body.submit;
	ullong	net64;

	net64 = htobe64(submit->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	*p++ = submit->pk_total;
	*p++ = submit->pk_number;
	*p++ = submit->reg_delivery;
	*p++ = submit->msg_level;

	memcpy(p, submit->service_id, CMPP_PROTO_SERVICE);
	p += CMPP_PROTO_SERVICE;

	*p++ = submit->fee_usertype;

	memcpy(p, submit->fee_terminal_id, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	*p++ = submit->tp_pid;
	*p++ = submit->tp_udhi;
	*p++ = submit->msg_fmt;

	memcpy(p, submit->msg_src, CMPP_PROTO_SP_ID);
	p += CMPP_PROTO_SP_ID;

	memcpy(p, submit->feetype, CMPP_PROTO_FEETYPE);
	p += CMPP_PROTO_FEETYPE;

	memcpy(p, submit->feecode, CMPP_PROTO_FEECODE);
	p += CMPP_PROTO_FEECODE;

	memcpy(p, submit->valid_time, CMPP_PROTO_TIME);
	p += CMPP_PROTO_TIME;

	memcpy(p, submit->at_time, CMPP_PROTO_TIME);
	p += CMPP_PROTO_TIME;

	memcpy(p, submit->src_id, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	*p++ = submit->destusr_tl;

	memcpy(p, submit->dest_id[0], CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	*p++ = submit->msg_length;

	memcpy(p, submit->msg_content, submit->msg_length);
	p += submit->msg_length;

	memcpy(p, submit->reserve, CMPP_PROTO_RESERVE);
	p += CMPP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
int make_submit_resp(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_submit_resp	*submit_resp = &pk->body.submit_resp;
	ullong	net64;

	net64 = htobe64(submit_resp->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	*p++ = submit_resp->result;

	*len = p - buf;
	return 0;
}
int make_deliver(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_deliver	*deliver = &pk->body.deliver;
	cmpp_report		report;
	ullong			net64;
	uint			net32;

	net64 = htobe64(deliver->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	memcpy(p, deliver->dest_id, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	memcpy(p, deliver->service_id, CMPP_PROTO_SERVICE);
	p += CMPP_PROTO_SERVICE;

	*p++ = deliver->tp_pid;
	*p++ = deliver->tp_udhi;
	*p++ = deliver->msg_fmt;

	memcpy(p, deliver->src_id, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	*p++ = deliver->reg_delivery;

	if(deliver->reg_delivery == 0){
		if(deliver->msg_length > CMPP_PROTO_CONTENT)
			return CMPP_STAT_SP_ELEN;
		*p++ = deliver->msg_length;

		memcpy(p, deliver->msg_content, deliver->msg_length);
		p += deliver->msg_length;
	}else{
		*p++ = CMPP_PACKET_LEN_REPORT;
		memcpy(&report, deliver->msg_content, sizeof(cmpp_report));

		net64 = htobe64(report.msg_id);
		memcpy(p, &net64, 8);
		p += 8;

		memcpy(p, &report.stat, CMPP_PROTO_REPORT_STAT);
		p += CMPP_PROTO_REPORT_STAT;

		memcpy(p, &report.submit_time, CMPP_PROTO_REPORT_TIME);
		p += CMPP_PROTO_REPORT_TIME;

		memcpy(p, &report.done_time, CMPP_PROTO_REPORT_TIME);
		p += CMPP_PROTO_REPORT_TIME;

		memcpy(p, &report.dest_id, CMPP_PROTO_MSISDN);
		p += CMPP_PROTO_MSISDN;

		net32 = htonl(report.smsc_seq);
		memcpy(p, &net32, 4);
		p += 4;
	}

	memcpy(p, deliver->reserve, CMPP_PROTO_RESERVE);
	p += CMPP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
int make_deliver_resp(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_deliver_resp	*deliver_resp = &pk->body.deliver_resp;
	ullong	net64;

	net64 = htobe64(deliver_resp->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	*p++ = deliver_resp->result;

	*len = p - buf;
	return 0;
}
int make_fwd(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_fwd		*fwd = &pk->body.fwd;
	cmpp_report		report;
	ullong			net64;
	uint			net32;

	memcpy(p, fwd->source_id, CMPP_PROTO_ISMG_ID);
	p += CMPP_PROTO_ISMG_ID;

	memcpy(p, fwd->destination_id, CMPP_PROTO_ISMG_ID);
	p += CMPP_PROTO_ISMG_ID;

	*p++ = fwd->nodescount;
	*p++ = fwd->msg_fwd_type;

	net64 = htobe64(fwd->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	*p++ = fwd->pk_total;
	*p++ = fwd->pk_number;
	*p++ = fwd->reg_delivery;
	*p++ = fwd->msg_level;

	memcpy(p, fwd->service_id, CMPP_PROTO_SERVICE);
	p += CMPP_PROTO_SERVICE;

	*p++ = fwd->fee_usertype;

	memcpy(p, fwd->fee_terminal_id, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	*p++ = fwd->tp_pid;
	*p++ = fwd->tp_udhi;
	*p++ = fwd->msg_fmt;

	memcpy(p, fwd->msg_src, CMPP_PROTO_SP_ID);
	p += CMPP_PROTO_SP_ID;

	memcpy(p, fwd->feetype, CMPP_PROTO_FEETYPE);
	p += CMPP_PROTO_FEETYPE;

	memcpy(p, fwd->feecode, CMPP_PROTO_FEECODE);
	p += CMPP_PROTO_FEECODE;

	memcpy(p, fwd->valid_time, CMPP_PROTO_TIME);
	p += CMPP_PROTO_TIME;

	memcpy(p, fwd->at_time, CMPP_PROTO_TIME);
	p += CMPP_PROTO_TIME;

	memcpy(p, fwd->src_id, CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	*p++ = fwd->destusr_tl;

	memcpy(p, fwd->dest_id[0], CMPP_PROTO_MSISDN);
	p += CMPP_PROTO_MSISDN;

	if(fwd->msg_fwd_type <= 1){
		*p++ = fwd->msg_length;
		memcpy(p, fwd->msg_content, fwd->msg_length);
		p += fwd->msg_length;
    }else{
        *p++ = CMPP_PACKET_LEN_REPORT;
        memcpy(&report, fwd->msg_content, sizeof(cmpp_report));

        net64 = htobe64(report.msg_id);
        memcpy(p, &net64, 8);
        p += 8;

        memcpy(p, &report.stat, CMPP_PROTO_REPORT_STAT);
        p += CMPP_PROTO_REPORT_STAT;

        memcpy(p, &report.submit_time, CMPP_PROTO_REPORT_TIME);
        p += CMPP_PROTO_REPORT_TIME;

        memcpy(p, &report.done_time, CMPP_PROTO_REPORT_TIME);
        p += CMPP_PROTO_REPORT_TIME;

        memcpy(p, &report.dest_id, CMPP_PROTO_MSISDN);
        p += CMPP_PROTO_MSISDN;

        net32 = htonl(report.smsc_seq);
        memcpy(p, &net32, 4);
        p += 4;
    }

	memcpy(p, fwd->reserve, CMPP_PROTO_RESERVE);
	p += CMPP_PROTO_RESERVE;

	*len = p - buf;
	return 0;
}
int make_fwd_resp(cmpp_packet *pk, char buf[], size_t *len)
{
	char	*p = buf;
	cmpp_fwd_resp	*fwd_resp = &pk->body.fwd_resp;
	ullong	net64;

	net64 = htobe64(fwd_resp->msg_id);
	memcpy(p, &net64, 8);
	p += 8;

	*p++ = fwd_resp->pk_total;
	*p++ = fwd_resp->pk_number;
	*p++ = fwd_resp->result;

	*len = p - buf;
	return 0;
}

/*
 * 3. print pk
 */
void print_header(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	log_printf("cmpp_header[len:%u,cmd:%#x,seq:%u]", header->len, header->cmd, header->seq);
}
void print_connect(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	cmpp_connect	*connect = &pk->body.connect;
	log_printf("cmpp_connect[len:%u,cmd:%#x,seq:%u,source:%s,auth:%s,version:%#x,timestamp:%u]",
			header->len, header->cmd, header->seq, connect->source, connect->auth, connect->version, connect->timestamp);
}
void print_connect_resp(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	cmpp_connect_resp	*resp = &pk->body.connect_resp;
	log_printf("cmpp_connect-resp[len:%u,cmd:%#x,seq:%u,status:%u,auth:%s,version:%#x]", 
			header->len, header->cmd, header->seq, resp->status, resp->auth, resp->version);
}
void print_submit(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	cmpp_submit	*submit = &pk->body.submit;
	log_printf("cmpp_submit[len:%u,cmd:%#x,seq:%u,msgid:%llx,pk_total:%u,pk_number:%u,reg_delivery:%u,msg_level:%u,service_id:%s,fee_usertype:%u,fee_terminal_id:%s,tp_pid:%u,tp_udhi:%u,msg_fmt:%u,msg_src:%s,feetype:%s,feecode:%s,valid_time:%s,at_time:%s,src_id:%s,destusr_tl:%u,dest_id:%s,msg_length:%u]",
			header->len, header->cmd, header->seq, 
			submit->msg_id, submit->pk_total, submit->pk_number, submit->reg_delivery, submit->msg_level, submit->service_id, submit->fee_usertype,
			submit->fee_terminal_id, submit->tp_pid, submit->tp_udhi, submit->msg_fmt, submit->msg_src, submit->feetype, submit->feecode,
			submit->valid_time, submit->at_time, submit->src_id, submit->destusr_tl, submit->dest_id[0], submit->msg_length);
}
void print_submit_resp(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	cmpp_submit_resp	*resp = &pk->body.submit_resp;
	log_printf("cmpp_submit_resp[len:%u,cmd:%#x,seq:%u,msgid:%llx,result:%u]",
			header->len, header->cmd, header->seq, resp->msg_id, resp->result);
}
void print_deliver(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	cmpp_deliver	*deliver = &pk->body.deliver;
	log_printf("cmpp_deliver[len:%u,cmd:%#x,seq:%u,msgid:%llx,dest_id:%s,service_id:%s,tp_pid:%u,tp_udhi:%u,msg_fmt:%u,src_id:%s,reg_delivery:%u,msg_length:%u]",
			header->len, header->cmd, header->seq, deliver->msg_id, deliver->dest_id, deliver->service_id, deliver->tp_pid, deliver->tp_udhi,
			deliver->msg_fmt, deliver->src_id, deliver->reg_delivery, deliver->msg_length);
}
void print_deliver_resp(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	cmpp_deliver_resp	*resp = &pk->body.deliver_resp;
	log_printf("cmpp_deliver_resp[len:%u,cmd:%#x,seq:%u,msgid:%llx,result:%u]", header->len, header->cmd, header->seq, resp->msg_id, resp->result);
}
void print_active(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	log_printf("cmpp_active[len:%u,cmd:%#x,seq:%u]", header->len, header->cmd, header->seq);
}
void print_active_resp(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	log_printf("cmpp_active_resp[len:%u,cmd:%#x,seq:%u]", header->len, header->cmd, header->seq);
}
void print_fwd(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	cmpp_fwd	*fwd = &pk->body.fwd;
	log_printf("cmpp_fwd[len:%u,cmd:%#x,seq:%u,source_id:%s,destination_id:%s,nodescount:%u,msg_fwd_type:%u,msgid:%llx,pk_total:%u,pk_number:%u,reg_delivery:%u,msg_level:%u,service_id:%s,fee_usertype:%u,fee_terminal_id:%s,tp_pid:%u,tp_udhi:%u,msg_fmt:%u,msg_src:%s,feetype:%s,feecode:%s,valid_time:%s,at_time:%s,src_id:%s,destusr_tl:%u,dest_id:%s,msg_length:%u]",
			header->len, header->cmd, header->seq, fwd->source_id, fwd->destination_id, fwd->nodescount, fwd->msg_fwd_type,
			fwd->msg_id, fwd->pk_total, fwd->pk_number, fwd->reg_delivery, fwd->msg_level, fwd->service_id, fwd->fee_usertype,
			fwd->fee_terminal_id, fwd->tp_pid, fwd->tp_udhi, fwd->msg_fmt, fwd->msg_src, fwd->feetype, fwd->feecode,
			fwd->valid_time, fwd->at_time, fwd->src_id, fwd->destusr_tl, fwd->dest_id[0], fwd->msg_length);
}
void print_fwd_resp(cmpp_packet *pk)
{
	cmpp_header	*header = &pk->header;
	cmpp_fwd_resp	*resp = &pk->body.fwd_resp;
	log_printf("cmpp_fwd_resp[len:%u,cmd:%#x,seq:%u,msgid:%llx,pk_total:%u,pk_number:%u,result:%u]", 
			header->len, header->cmd, header->seq, resp->msg_id, resp->pk_total, resp->pk_number, resp->result);
}
