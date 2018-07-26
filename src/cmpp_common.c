#include "cmpp_common.h"

/* trans init */
void trans_init(trans_t *trans)
{
	memset(trans, 0, sizeof(trans_t));
	trans->connfd = -1;
	trans->timeout = 60;
	trans->times = 3;
	return;
}
void trans_destroy(trans_t *trans)
{
	if(trans->connfd > -1)
		close(trans->connfd);
	cmpp_window_destroy(&trans->pwin);
	return;
}

/* recv cmpp packet */
int cmpp_recv_packet(int connfd, cmpp_packet *pk)
{
	int		ret, net32;
	char	buf[CMPP_PACKET_LEN_MAX];
	uint	len;
	ssize_t	size;

	size = recv(connfd, buf, 4, 0);
	if(size != 4){
		log_error(recv, EAGAIN);
		return EAGAIN;
	}
	memcpy(&net32, buf, 4);
	len = ntohl(net32);
	if(len < CMPP_PACKET_LEN_HEADER || len > CMPP_PACKET_LEN_MAX)
		return CMPP_STAT_SP_ELEN;
	size = recv(connfd, buf+4, len-4, 0);
	if(size != len-4){
		log_error(recv, EAGAIN);
		return EAGAIN;
	}
	ret = cmpp_parse_buf2pk(buf, len, pk);
	if(ret != 0){
		log_error(cmpp_parse_buf2pk, ret);
		return ret;
	}
	return 0;
}

/* send cmpp packet */
int cmpp_send_packet(int connfd, cmpp_packet *pk)
{
	int		ret;
	char	buf[CMPP_PACKET_LEN_MAX];
	size_t	len;
	ssize_t	size;

	ret = cmpp_make_pk2buf(pk, buf, &len);
	if(ret != 0){
		log_error(cmpp_make_pk2buf, ret);
		return ret;
	}
	if(len < CMPP_PACKET_LEN_HEADER || len > CMPP_PACKET_LEN_MAX)
		return CMPP_STAT_SP_ELEN;
	size = send(connfd, buf, len, 0);
	if(size != len){
		log_error(send, errno);
		return errno;
	}
	return 0;
}

/* sliding window */
int cmpp_window_init(window_t *pwin, uint window, uint timeout)
{
	if(pwin == NULL || window == 0 || window > 100)
		return EINVAL;
	pwin->window = window;
	pwin->timeout = timeout;
	pwin->count = 0;
	pwin->elem = calloc(1, sizeof(window_elem) * window);
	return 0;
}
int cmpp_window_add(window_t *pwin, uint key, cmpp_packet *value)
{
	uint	i;
	if(pwin == NULL || value == NULL)
		return EINVAL;
	if(pwin->count >= pwin->window)
		return COM_EFULL;
	i = key % (pwin->window);
	if(pwin->elem[i].status == 0){
		pwin->elem[i].status = 1;
		pwin->elem[i].key = key;
		pwin->elem[i].timestamp = time(NULL);
		memcpy(&pwin->elem[i].value, value, sizeof(cmpp_packet));
		pwin->count++;
		return 0;
	}
	for(i=0; i<pwin->window; i++){
		if(pwin->elem[i].status == 0){
			pwin->elem[i].status = 1;
			pwin->elem[i].key = key;
			pwin->elem[i].timestamp = time(NULL);
			memcpy(&pwin->elem[i].value, value, sizeof(cmpp_packet));
			pwin->count++;
			return 0;
		}
	}
	return COM_EFAIL;
}
int cmpp_window_del(window_t *pwin, uint key, cmpp_packet *value)
{
	uint	i;
	if(pwin == NULL || value == NULL)
		return EINVAL;
	if(pwin->count == 0)
		return COM_EEMPTY;
	i = key % (pwin->window);
	if(pwin->elem[i].status == 1 && pwin->elem[i].key == key){
		pwin->elem[i].status = 0;
		memcpy(value, &pwin->elem[i].value, sizeof(cmpp_packet));
		pwin->count--;
		return 0;
	} 
	for(i=0; i<pwin->window; i++){
		if(pwin->elem[i].status == 1 && pwin->elem[i].key == key){
			pwin->elem[i].status = 0;
			memcpy(value, &pwin->elem[i].value, sizeof(cmpp_packet));
			pwin->count--;
			return 0;
		} 
	}
	return COM_EFAIL;
}
int cmpp_window_timeout(window_t *pwin, cmpp_packet *value)
{
	int		i, ret;
	time_t	now;
	if(pwin == NULL || value == NULL)
		return EINVAL;
	if(pwin->count == 0)
		return COM_ENOFOUND;
	now = time(NULL);
	for(i=0; i<pwin->window; i++){
		if(pwin->elem[i].status == 1 && (now - pwin->elem[i].timestamp > pwin->timeout)){
			ret = cmpp_window_del(pwin, pwin->elem[i].key, value);
			return ret;
		}
	}
	return COM_ENOFOUND;
}
int cmpp_window_get_free(window_t *pwin, uint *count)
{
	if(pwin == NULL || count == NULL)
		return EINVAL;
	if(pwin->count > pwin->window){
		*count = 0;
		return COM_EFAIL;
	}
	*count = pwin->window - pwin->count;
	return 0;
}
void cmpp_window_destroy(window_t *pwin)
{
	if(pwin->elem != NULL)
		free(pwin->elem);
}

/* deliver msgid */
int create_deliver_msgid(deliver_msgid_t **dmsgid, char *ismg_id)
{
	int     ret;
	pthread_mutexattr_t mattr;

	ret = com_mmap_create((void**)dmsgid, sizeof(deliver_msgid_t));
	if(ret != 0)
		return ret;

	pthread_mutexattr_init(&mattr);
	pthread_mutexattr_settype(&mattr, PTHREAD_MUTEX_ERRORCHECK);
	pthread_mutexattr_setpshared(&mattr, PTHREAD_PROCESS_SHARED);
	ret = pthread_mutex_init(&(*dmsgid)->lock, &mattr);
	if(ret != 0)
		return ret;

	strcpy((*dmsgid)->ismgid, ismg_id);
	return 0;
}
int get_deliver_msgid(deliver_msgid_t *dmsgid, ullong *msgid)
{
	int     ret;
	time_t  now;
	struct  tm tm;
	ullong	tmp;

	ret = pthread_mutex_lock(&dmsgid->lock);
	if(ret != 0)
		return ret;
	now = time(NULL);
	if(now == dmsgid->last){
		*msgid = ++dmsgid->msgid;
	}else{
		dmsgid->last = now;
		localtime_r(&now, &tm);
		tmp = tm.tm_mon+1; *msgid = (tmp << 60);
		tmp = tm.tm_mday; *msgid += (tmp << 55);
		tmp = tm.tm_hour; *msgid += (tmp << 50);
		tmp = tm.tm_min; *msgid += (tmp << 44);
		tmp = tm.tm_sec; *msgid += (tmp << 38);
		tmp = atoi(dmsgid->ismgid); *msgid += (tmp << 16);
		*msgid += 1;
		dmsgid->msgid = *msgid;
	}
	pthread_mutex_unlock(&dmsgid->lock);
	return 0;
}
