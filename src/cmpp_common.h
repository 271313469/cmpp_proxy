#ifndef	CMPP_COMMON_H
#define	CMPP_COMMON_H

#include "cmpp_proto.h"
#include "proxy.h"

typedef struct trans_t		trans_t;
typedef struct window_t		window_t;
typedef struct window_elem	window_elem;
typedef struct deliver_msgid_t	deliver_msgid_t;

struct window_elem {
	uint	status;
	uint	key;
	time_t	timestamp;
    cmpp_packet value;
};
struct window_t {
	uint	window;
	uint	timeout;
	uint	count;
	window_elem	*elem;
};
struct trans_t {
	int		connfd;
	uint	status;		//0:unlogin, 1:login
	uint	timeout;
	uint	times;
	uint	window;
	uint	curtimes;
	window_t	pwin;
	time_t	last;		//last update time
};
struct deliver_msgid_t {
    pthread_mutex_t lock;
    time_t  last;
    char    ismgid[7];
    ullong	msgid;
};

void trans_init(trans_t *trans);
void trans_destroy(trans_t *trans);

int cmpp_send_packet(int connfd, cmpp_packet *pk);
int cmpp_recv_packet(int connfd, cmpp_packet *pk);
int cmpp_window_init(window_t *pwin, uint window, uint timeout);
int cmpp_window_add(window_t *pwin, uint key, cmpp_packet *value);
int cmpp_window_del(window_t *pwin, uint key, cmpp_packet *value);
int cmpp_window_timeout(window_t *pwin, cmpp_packet *value);
int cmpp_window_get_free(window_t *pwin, uint *count);
void cmpp_window_destroy(window_t *pwin);

int create_deliver_msgid(deliver_msgid_t *dmsgid, char *ismgid);
int get_deliver_msgid(deliver_msgid_t *dmsgid, ullong *msgid);

int cmpp_client_handle_login(trans_t *trans, rsmg_node *rsmg);
int cmpp_client_handle_timeout(trans_t *trans);
int cmpp_client_handle_send(trans_t *trans);
int cmpp_client_handle_recv(trans_t *trans);

int cmpp_server_handle_timeout(trans_t *trans);
int cmpp_server_handle_recv(trans_t *trans);

#endif

