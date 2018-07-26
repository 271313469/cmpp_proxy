#ifndef PROXY_H
#define PROXY_H

#include "cmpp_proto.h"

typedef struct msg_flow		msg_flow;
typedef struct ismg_desc	ismg_desc;
typedef struct ismg_node	ismg_node;
typedef struct rsmg_desc	rsmg_desc;
typedef struct rsmg_node	rsmg_node;
typedef struct db_desc		db_desc;
typedef struct db_node		db_node;
typedef struct cmpp_msgbuf	cmpp_msgbuf;

struct msg_flow {
	ullong	mo_ok;
	ullong	mt_ok;
	ullong	mtsr_ok;
};
struct ismg_desc {
	char	ismg_id[CMPP_PROTO_ISMG_ID + 1];
	char	ip[16];
	ushort	port;
	uchar	protocol;
	uint	max_rsmg;
};
struct ismg_node {
	ismg_desc	desc;
	uint		curlink;
	msg_flow	flow;
};
struct rsmg_desc {
    uint    idx;
    char    rsmg_id[CMPP_PROTO_ISMG_ID + 1];
    char    ip[16];
	ushort	port;
	uchar	protocol;
	char	send_pwd[CMPP_PROTO_ATUH];
	char	recv_pwd[CMPP_PROTO_ATUH];
    uint    send_links;
    uint    recv_links;
    uint    window;
    uint    timeout;
    uint    times;
};
struct rsmg_node {
    rsmg_desc	desc;
    uint        status;
    uint        slink;
    uint        rlink;
    msg_flow    flow;
};
struct db_desc {
	char	ip[16];
	ushort	port;
	char	database[32];
	char	user[16];
	char	pwd[16];
	uint	interval;
	uint	limit;
};
struct db_node {
	db_desc		desc;
	msg_flow	flow;
};

struct cmpp_msgbuf {
	long	mtype;
	char	mtext[CMPP_PACKET_LEN_MAX];
};


int read_ismg_conf(char *filename);
int read_rsmg_conf(char *filename);
int read_db_conf(char *filename);
void print_ismg_desc(ismg_desc *desc);
void print_rsmg_desc(rsmg_desc *desc);
void print_db_desc(db_desc *desc);

#endif
