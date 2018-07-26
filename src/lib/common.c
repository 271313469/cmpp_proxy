#include "common.h"

int	g_log_type;
int	g_log_fd = -1;

int log_init(int type, char *filename)
{
	g_log_type = type;
	if(g_log_fd != -1)
		close(g_log_fd);

	if(type == LOG_FILETYPE_NONE){
	}else if(type == LOG_FILETYPE_REGULAR){
		g_log_fd = open(filename, O_WRONLY | O_CREAT | O_NONBLOCK, 0600);
		if(g_log_fd < 0){
			return errno;
		}
	}else if(type == LOG_FILETYPE_FIFO){
reopen:
		g_log_fd = open(filename, O_RDWR | O_NONBLOCK, 0);
		if(g_log_fd < 0){
			mkfifo(filename, 0600);
			goto reopen;
		}
	}else{
		return EINVAL;
	}
	return 0;
}
int log_printf(const char *fmt, ...)
{
	char	buf[PIPE_BUF];
	char	log[PIPE_BUF];
	struct	timeval tv;
	struct	tm tm;
	va_list	ap;

	va_start(ap, fmt);
	vsprintf(buf, fmt, ap);
	va_end(ap);
	gettimeofday(&tv, NULL);
	localtime_r(&tv.tv_sec, &tm);
	if(g_log_type == LOG_FILETYPE_NONE){
		printf("%04d%02d%02d%02d%02d%02d.%lu-%u-%lu>%s\n", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				tv.tv_usec, getpid(), pthread_self(), buf);
	}else{
		sprintf(log, "%04d%02d%02d%02d%02d%02d.%lu-%u-%lu>%s\n", tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
				tv.tv_usec, getpid(), pthread_self(), buf);
		write(g_log_fd, log, strlen(log));
	}
	return 0;
}

int com_str_isdigit(char *str)
{
	int     i;
	assert(str != NULL);
	if(strlen(str) == 0)
		return 0;
	for(i=0; str[i]!=0; i++)
		if(!isdigit(str[i]))
			return 0;
	return 1;
}
int com_str_ishex(char *str)
{
	int     i;
	assert(str != NULL);
	if(strlen(str) == 0)
		return 0;
	for(i=0; str[i]!=0; i++)
		if(!isxdigit(str[i]))
			return 0;
	return 1;
}
int com_str_isasc(char *str)
{
	int     i;
	assert(str != NULL);
	if(strlen(str) == 0)
		return 0;
	for(i=0; str[i]!=0; i++)
		if(!isascii(str[i]))
			return 0;
	return 1;
}
char *com_str_ltrim(char *str)
{
	char *p;
	assert(str != NULL);
	for(p=str; *p!='\0'; p++)
		if(!isspace(*p))
			break;
	memmove(str, p, strlen(p)+1);
	return str;
}       
char *com_str_rtrim(char *str)
{
	char *p;
	assert(str != NULL);
	p = str + strlen(str)-1;
	while((p!=str) && isspace(*p)){
		*p = '\0'; 
		p--; 
	}       
	return str;
}
char *com_str_trim(char *str)
{
	com_str_ltrim(str);
	com_str_rtrim(str);
	return str;
}

int com_cfg_get_value(char *filename, char *key, char *value)
{
	FILE    *fp = NULL;
	char    buf[512];
	char    bufkey[256];
	char    bufvalue[256];
	char    *p = NULL;
	int     flag = 0;
	int     len = 0;

	if(filename == NULL || key == NULL || value == NULL)
		return EINVAL;
	fp = fopen(filename, "r");
	if(fp == NULL){
		return errno;
	}
	while(fgets(buf, sizeof(buf), fp) != NULL){
		//check
		com_str_trim(buf);
		if(buf[0] == '#')
			continue;
		//get = position
		if((p = strchr(buf, '=')) == NULL)
			return EINVAL;
		//get cfg key
		len = p - buf;
		memset(bufkey, 0, sizeof(bufkey));
		strncpy(bufkey, buf, len);
		com_str_rtrim(bufkey);
		//get cfg value
		if(!strcmp(bufkey, key)){
			memset(bufvalue, 0, sizeof(bufvalue));
			strcpy(bufvalue, p+1);
			com_str_ltrim(bufvalue);
			strcpy(value, bufvalue);
			flag = 1;
			break;
		}
	}
	fclose(fp);
	if(flag)
		return 0;
	else
		return COM_ENOFOUND;
}
int com_cfg_get_row(char *filename, int row, char *value)
{
	FILE    *fp=NULL;
	char    buf[512];
	int     flag=0;
	int     x=0;

	if(filename == NULL || row <= 0 || value == NULL)
		return EINVAL;
	fp = fopen(filename, "r");
	if(fp == NULL){
		return errno;
	}
	while(fgets(buf, sizeof(buf), fp) != NULL){
		//check
		com_str_ltrim(buf);
		com_str_rtrim(buf);
		if(buf[0] == '#')
			continue;
		if(++x < row)
			continue;
		//get value
		strcpy(value, buf);
		flag = 1;
		break;
	}
	fclose(fp);
	if(flag)
		return 0;
	else
		return COM_ENOFOUND;
}

void process_detach()
{
	int     i;
	pid_t   pid;
	int     fd0, fd1, fd2;

	umask(0);
	if((pid = fork()) < 0)
		fprintf(stderr, "fork failed\n");
	if(pid > 0)
		exit(0);
	signal(SIGHUP, SIG_IGN);
	setsid();
	if((pid = fork()) < 0)
		fprintf(stderr, "fork failed\n");
	else if(pid > 0)
		exit(0);
	for(i=0; i<getdtablesize(); i++)
		(void)close(i);
	fd0 = open("/dev/null", O_RDWR);
	fd1 = dup(0);
	fd2 = dup(0);
	if(fd0 != 0 || fd1 != 1 || fd2 != 2)
		exit(1);
	sleep(3);
	return ;
}

int com_mmap_create(void **pmmap, size_t size)
{
	int     fd;
	fd = open("/dev/zero",O_RDWR);
	if(fd < 0)
		return errno;
	(*pmmap) = mmap(NULL,(off_t)size,PROT_READ|PROT_WRITE, MAP_SHARED,fd,0);
	close(fd);
	if((*pmmap) == MAP_FAILED)
		return errno;
	memset(*pmmap, 0, (off_t)size);
	return 0;
}

int com_socket_create_tcp_listen(int *sockfd, char *ip, int port,int backlog)
{
	int		ret;
	struct	sockaddr_in serv_addr;

	if(sockfd == NULL || ip == NULL)
		return EINVAL;

	*sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == *sockfd){
		log_error(socket, errno);
		return errno;
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = inet_addr(ip);
	bzero(&serv_addr.sin_zero, 8);

	ret = bind(*sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));
	if(-1 == ret){
		log_error(bind, errno);
		return errno;
	}
	ret = listen(*sockfd, backlog);
	if(-1 == ret){
		log_error(listen, errno);
		return errno;
	}
	return 0;
}
int com_socket_create_tcp_connect(int *sockfd, char *ip, int port)
{
	int		ret;
	struct	sockaddr_in serv_addr;

	if(sockfd == NULL || ip == NULL)
		return EINVAL;

	*sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if(-1 == *sockfd){
		log_error(socket, errno);
		return errno;
	}
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = inet_addr(ip);
	bzero(&serv_addr.sin_zero, 8);

	ret = connect(*sockfd, (struct sockaddr *)&serv_addr, sizeof(struct sockaddr_in));
	if(ret < 0){
		log_error(connect, errno);
		return errno;
	}
	return 0;
}
