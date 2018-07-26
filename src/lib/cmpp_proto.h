#ifndef CMPP_PROTO_H
#define CMPP_PROTO_H

#include "common.h"

/*
 * CMD_ID
 */
#define	CMPP_CMD_CONNECT				0x00000001
#define	CMPP_CMD_CONNECT_RESP			0x80000001
#define	CMPP_CMD_TERMINATE				0x00000002
#define	CMPP_CMD_TERMINATE_RESP			0x80000002
#define	CMPP_CMD_SUBMIT					0x00000004
#define	CMPP_CMD_SUBMIT_RESP			0x80000004
#define	CMPP_CMD_DELIVER				0x00000005
#define	CMPP_CMD_DELIVER_RESP			0x80000005
#define	CMPP_CMD_QUERY					0x00000006
#define	CMPP_CMD_QUERY_RESP				0x80000006
#define	CMPP_CMD_CANCEL					0x00000007
#define	CMPP_CMD_CANCEL_RESP			0x80000007
#define	CMPP_CMD_ACTIVE_TEST			0x00000008
#define	CMPP_CMD_ACTIVE_TEST_RESP		0x80000008
#define CMPP_CMD_FWD					0x00000009
#define CMPP_CMD_FWD_RESP				0x80000009


/*
 * PROTO_LEN
 */
#define	CMPP_PROTO_ISMG_ID		6
#define	CMPP_PROTO_SP_ID		6
#define	CMPP_PROTO_SP_CODE		21
#define CMPP_PROTO_ATUH			16
#define CMPP_PROTO_SERVICE		10
#define CMPP_PROTO_MSISDN		21
#define CMPP_PROTO_FEETYPE		2
#define CMPP_PROTO_FEECODE		6
#define CMPP_PROTO_TIME			17
#define CMPP_PROTO_DESTUSERTL	1
#define CMPP_PROTO_CONTENT		160
#define CMPP_PROTO_RESERVE		8	
#define CMPP_PROTO_QUERY_TIME	8	
#define CMPP_PROTO_QUERY_CODE	10	
#define CMPP_PROTO_REPORT_STAT	7
#define CMPP_PROTO_REPORT_TIME	10	

/*
 * ERR_CODE
 */
#define CMPP_STAT_CONNECT_SUCCESS	0
#define CMPP_STAT_CONNECT_ESTRUCT	1
#define CMPP_STAT_CONNECT_ESRC		2
#define CMPP_STAT_CONNECT_EAUTH		3
#define CMPP_STAT_CONNECT_EVERSION	4
#define CMPP_STAT_CONNECT_EOTHER	5

#define CMPP_STAT_SP_SUCCESS	0
#define CMPP_STAT_SP_ESTRUCT	1
#define CMPP_STAT_SP_ECMD		2
#define CMPP_STAT_SP_ESEQ		3
#define CMPP_STAT_SP_ELEN		4
#define CMPP_STAT_SP_EFEECODE	5
#define CMPP_STAT_SP_ECONTENT	6
#define CMPP_STAT_SP_EBUSYCODE	7
#define CMPP_STAT_SP_EFLOW		8
#define CMPP_STAT_SP_EOTHER		9
#define CMPP_STAT_SP_ESRC_ID	10
#define CMPP_STAT_SP_EMSG_SRC	11
#define CMPP_STAT_SP_EFEE_ID	12
#define CMPP_STAT_SP_EDEST_ID	13

/*
 * BUSI
 */
#define	CMPP_PACKET_LEN_MAX				sizeof(struct cmpp_packet)
#define	CMPP_PACKET_LEN_HEADER			12
#define	CMPP_PACKET_LEN_CONNECT			39	//12+27
#define	CMPP_PACKET_LEN_CONNECT_RESP	30	//12+18
#define	CMPP_PACKET_LEN_SUBMIT			319	//12+307
#define	CMPP_PACKET_LEN_SUBMIT_RESP		21	//12+9
#define	CMPP_PACKET_LEN_DELIVER			245	//12+233
#define	CMPP_PACKET_LEN_DELIVER_RESP	21	//12+9
#define	CMPP_PACKET_LEN_QUERY			39	//12+27
#define	CMPP_PACKET_LEN_QUERY_RESP		63	//12+51
#define	CMPP_PACKET_LEN_REPORT			60	
#define	CMPP_PACKET_LEN_ACTIVE			12
#define	CMPP_PACKET_LEN_ACTIVE_RESP		13
#define CMPP_PACKET_LEN_FWD				333	//12+321
#define CMPP_PACKET_LEN_FWD_RESP		23	//12+11

/*
 * STRUCT
 */
typedef struct cmpp_header			cmpp_header;
typedef struct cmpp_connect			cmpp_connect;
typedef struct cmpp_connect_resp	cmpp_connect_resp;
typedef struct cmpp_submit			cmpp_submit;
typedef struct cmpp_submit_resp		cmpp_submit_resp;
typedef struct cmpp_query			cmpp_query;
typedef struct cmpp_query_resp		cmpp_query_resp;
typedef struct cmpp_deliver			cmpp_deliver;
typedef struct cmpp_deliver_resp	cmpp_deliver_resp;
typedef struct cmpp_report			cmpp_report;
typedef struct cmpp_header			cmpp_active;
typedef struct cmpp_active_resp		cmpp_active_resp;
typedef struct cmpp_fwd				cmpp_fwd;
typedef struct cmpp_fwd_resp		cmpp_fwd_resp;
typedef struct cmpp_packet			cmpp_packet;

struct cmpp_header
{
	uint	len; //消息总长度(含消息头及消息体)
	uint	cmd; //命令或响应类型
	uint	seq; //消息流水号,顺序累加,步长为1,循环使用
};
struct cmpp_connect
{
	char	source[CMPP_PROTO_SP_ID + 1]; //源地址，此处为SP_Id，即SP的企业代码
	char	auth[CMPP_PROTO_ATUH + 1]; //MD5(source + 000000000 + shared secret + MMDDHHMMSS)
	uchar	version; //0x20, 0x30
	uint	timestamp; //MMDDHHMMSS
};
struct cmpp_connect_resp
{
	uchar	status; //0：正确 1：消息结构错 2：非法源地址 3：认证错 4：版本太高
	char	auth[CMPP_PROTO_ATUH + 1];
	uchar	version; //服务器支持的最高版本号
};
struct cmpp_submit
{
	ullong	msg_id; //由SP侧短信网关本身产生，本处填空
	uchar	pk_total; //相同Msg_Id的信息总条数，从1开始
	uchar	pk_number; //相同Msg_Id的信息序号，从1开始
	uchar	reg_delivery; //是否要求返回状态确认报告 0：不需要 1：需要 2：产生SMC话单
	uchar	msg_level; //信息级别
	char	service_id[CMPP_PROTO_SERVICE + 1]; //业务类型是数字字母和符号的组合
	uchar	fee_usertype; //计费用户类型字段 0：对目的终端MSISDN计费； 1：对源终端MSISDN计费； 2：对SP计费; 3：表示本字段无效
	char	fee_terminal_id[CMPP_PROTO_MSISDN + 1]; //被计费用户的号码（如本字节填空，则表示本字段无效，对谁计费参见Fee_UserType字段）
	uchar	tp_pid;
	uchar	tp_udhi;
	uchar	msg_fmt; //0:ASCII 3:短信写卡操作 4:bit 8:UCS2 15:GB
	char	msg_src[CMPP_PROTO_SP_ID + 1]; //信息内容来源(SP_Id)
	char	feetype[CMPP_PROTO_FEETYPE + 1]; //资费类别01：免费 02：按条 03：按月 04：封顶 05：由SP实现
	char	feecode[CMPP_PROTO_FEECODE + 1]; //资费代码（以分为单位）
	char	valid_time[CMPP_PROTO_TIME + 1]; //存活有效期
	char	at_time[CMPP_PROTO_TIME + 1]; //定时发送时间
	char	src_id[CMPP_PROTO_MSISDN + 1]; //源号码，SP的服务代码或前缀为服务代码的长号码
	uchar	destusr_tl; //接收信息的用户数量(小于100个用户)
	char	dest_id[CMPP_PROTO_DESTUSERTL][CMPP_PROTO_MSISDN + 1]; //接收业务的MSISDN号码
	uchar	msg_length; //信息长度(msg_fmt值为0时：<160个字节；其它<=140个字节)
	char	msg_content[CMPP_PROTO_CONTENT]; //信息内容
	char	reserve[CMPP_PROTO_RESERVE];
};
struct cmpp_submit_resp
{
	ullong	msg_id; //SP根据请求和应答消息的Sequence_Id一致性就可得到CMPP_Submit消息的Msg_Id
	uchar	result; //0正确1消息结构错2命令字错3消息序号重复4消息长度错5资费代码错6超过最大信息长7业务代码错8流量控制错9~ 其他错误
};
struct cmpp_deliver
{
	ullong	msg_id; //时间格式为MMDDHHMMSS:bit64~bit39 短信网关号码:bit38~bit17 序列号:bit16~bit1
	char	dest_id[CMPP_PROTO_MSISDN + 1]; //目的号码 SP的服务代码，一般4-6位，或者是前缀为服务代码的长号码；该号码是手机用户短消息的被叫号码
	char	service_id[CMPP_PROTO_SERVICE + 1];
	uchar	tp_pid;
	uchar	tp_udhi;
	uchar	msg_fmt;
	char	src_id[CMPP_PROTO_MSISDN + 1]; //源终端MSISDN号码（状态报告时填为CMPP_SUBMIT消息的目的终端号码）
	uchar	reg_delivery; //是否为应答信息 0：非应答信息 1：状态报告
	uchar	msg_length;
	char	msg_content[CMPP_PROTO_CONTENT];
	char	reserve[CMPP_PROTO_RESERVE];
};
struct cmpp_deliver_resp
{
	ullong	msg_id;
	uchar	result;
};
struct cmpp_report
{
	ullong	msg_id;
	char	stat[CMPP_PROTO_REPORT_STAT + 1]; //DELIVRD EXPIRED DELETED UNDELIV ACCEPTD UNKNOWN REJECTD
	char	submit_time[CMPP_PROTO_REPORT_TIME + 1]; //YYMMDDHHMM（YY为年的后两位00-99，MM：01-12，DD：01-31，HH：00-23，MM：00-59）
	char	done_time[CMPP_PROTO_REPORT_TIME + 1];
	char	dest_id[CMPP_PROTO_MSISDN + 1];
	uint	smsc_seq; //取自SMSC发送状态报告的消息体中的消息标识
};
struct cmpp_active_resp
{
	uchar	reserved;
};
struct cmpp_fwd
{
	char	source_id[CMPP_PROTO_ISMG_ID + 1]; //源网关的代码（右对齐，左补0）
	char	destination_id[CMPP_PROTO_ISMG_ID + 1]; //目的网关代码（右对齐，左补0）
	uchar	nodescount; //经过的网关数量
	uchar	msg_fwd_type; //前转的消息类型 0：MT前转 1：MO前转 2：MT时的状态报告 3：MO时的状态报告
    ullong  msg_id; //由SP侧短信网关本身产生，本处填空
    uchar   pk_total; //相同Msg_Id的信息总条数，从1开始
    uchar   pk_number; //相同Msg_Id的信息序号，从1开始
    uchar   reg_delivery; //是否要求返回状态确认报告 0：不需要 1：需要 2：产生SMC话单
    uchar   msg_level; //信息级别
    char    service_id[CMPP_PROTO_SERVICE + 1]; //业务类型是数字字母和符号的组合
    uchar   fee_usertype; //计费用户类型字段 0：对目的终端MSISDN计费； 1：对源终端MSISDN计费； 2：对SP计费; 3：表示本字段无效
    char    fee_terminal_id[CMPP_PROTO_MSISDN + 1]; //被计费用户的号码（如本字节填空，则表示本字段无效，对谁计费参见Fee_UserType字段）
    uchar   tp_pid;
    uchar   tp_udhi;
    uchar   msg_fmt; //0:ASCII 3:短信写卡操作 4:bit 8:UCS2 15:GB
    char    msg_src[CMPP_PROTO_SP_ID + 1]; //信息内容来源(SP_Id)
    char    feetype[CMPP_PROTO_FEETYPE + 1]; //资费类别01：免费 02：按条 03：按月 04：封顶 05：由SP实现
    char    feecode[CMPP_PROTO_FEECODE + 1]; //资费代码（以分为单位）
    char    valid_time[CMPP_PROTO_TIME + 1]; //存活有效期
    char    at_time[CMPP_PROTO_TIME + 1]; //定时发送时间
    char    src_id[CMPP_PROTO_MSISDN + 1]; //源号码，SP的服务代码或前缀为服务代码的长号码
    uchar   destusr_tl; //接收信息的用户数量(小于100个用户)
    char    dest_id[CMPP_PROTO_DESTUSERTL][CMPP_PROTO_MSISDN + 1]; //接收业务的MSISDN号码
    uchar   msg_length; //信息长度(msg_fmt值为0时：<160个字节；其它<=140个字节)
    char    msg_content[CMPP_PROTO_CONTENT]; //信息内容
    char    reserve[CMPP_PROTO_RESERVE];
};
struct cmpp_fwd_resp
{
	ullong	msg_id; //SP根据请求和应答消息的Sequence_Id一致性就可得到CMPP_Submit消息的Msg_Id
    uchar   pk_total; //相同Msg_Id的信息总条数，从1开始
    uchar   pk_number; //相同Msg_Id的信息序号，从1开始
	uchar	result; //0正确1消息结构错2命令字错3消息序号重复4消息长度错5资费代码错6超过最大信息长7业务代码错8流量控制错9~ 其他错误
};
struct cmpp_packet
{
	cmpp_header	header;
	union {
		cmpp_connect		connect;
		cmpp_connect_resp	connect_resp;
		cmpp_submit			submit;
		cmpp_submit_resp	submit_resp;
		cmpp_deliver		deliver;
		cmpp_deliver_resp	deliver_resp;
		cmpp_fwd			fwd;
		cmpp_fwd_resp		fwd_resp;
	} body;
};

int cmpp_parse_buf2pk(char buf[], size_t len, cmpp_packet *pk);
int cmpp_make_pk2buf(cmpp_packet *pk, char buf[], size_t *len);
void cmpp_print_pk(cmpp_packet *pk);

#endif
