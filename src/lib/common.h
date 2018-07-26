#ifndef COMMON_H 
#define COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <dirent.h>
#include <time.h>
#include <stdarg.h>
#include <ctype.h>
#include <setjmp.h>

#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/mman.h>
#include <endian.h>
#include <sys/ipc.h>
#include <sys/msg.h>

#define COM_STATU_START		1000
#define COM_EINVAL		COM_STATU_START+1
#define COM_EFAIL		COM_STATU_START+2
#define COM_EEXIST		COM_STATU_START+3
#define COM_ENOFOUND	COM_STATU_START+4
#define COM_ECHILD		COM_STATU_START+5
#define COM_EENOMEM		COM_STATU_START+6
#define COM_EFULL		COM_STATU_START+7
#define COM_EEMPTY		COM_STATU_START+8
#define COM_ETIMEOUT	COM_STATU_START+9

#define log_error(name,stat) log_printf("%s error(%d),(%s)(%d)(%s)\n", #name,stat,__FILE__,__LINE__,__FUNCTION__)

enum {
	LOG_FILETYPE_NONE,
	LOG_FILETYPE_REGULAR,
	LOG_FILETYPE_FIFO,
};

typedef unsigned char	uchar;
typedef unsigned short	ushort;
typedef unsigned int	uint;
typedef unsigned long long ullong;

int log_init(int type, char *filename);
int log_printf(const char *fmt, ...);


int com_str_isdigit(char *str);
int com_str_ishex(char *str);
int com_str_isasc(char *str);
char *com_str_ltrim(char *str);
char *com_str_rtrim(char *str);
char *com_str_trim(char *str);

int com_cfg_get_value(char *filename, char *key, char *value);
int com_cfg_get_row(char *filename, int row, char *value);

void process_detach();

int com_mmap_create(void **pmmap, size_t size);

int com_socket_create_tcp_listen(int *sockfd, char *ip, int port,int backlog);
int com_socket_create_tcp_connect(int *sockfd, char *ip, int port);

#endif
