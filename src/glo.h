#ifndef GLO_H
#define GLO_H

#include "cmpp_common.h"
#include "proxy.h"

#define CONF_PATH_ISMG	"conf/ismg.conf"
#define CONF_PATH_RSMG	"conf/rsmg.conf"
#define CONF_PATH_DB	"conf/db.conf"

#define LOG_FIFO_ISMG_SEND	"fifo/ismgsend.fifo"
#define LOG_FIFO_ISMG_RECV	"fifo/ismgrecv.fifo"
#define LOG_FIFO_DB			"fifo/db.fifo"

#define LOG_FILE_ISMG_SEND	"log/ismgsend.log"
#define LOG_FILE_ISMG_RECV	"log/ismgrecv.log"
#define LOG_FILE_DB			"log/db.log"

#define	G_RSMG_NUM_MAX	100
#define	G_MQID_DELIVER	100000000
#define	G_MQID_SUBMIT	200000000
#define	G_MQID_RETRANS	300000000

struct ismg_node	*g_ismg_node;
struct rsmg_node	*g_rsmg_node[G_RSMG_NUM_MAX];
struct db_node		*g_db_node;
//struct msgid_t		*g_msgid;

#endif
