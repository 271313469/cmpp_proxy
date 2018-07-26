#include "proxy.h"
#include "glo.h"

int read_ismg_conf(char *filename)
{
	int     ret;
	char    value[256];

	//g_ismg_node = calloc(1, sizeof(ismg_node));
	ret = com_mmap_create((void**)&g_ismg_node, sizeof(ismg_node));
	if(ret != 0){
		log_error(com_mmap_create, ret);
		return ret;
	}

	ret = com_cfg_get_value(filename, "ismg_id", value);
	if(ret != 0){
		log_printf("read_ismg_conf ismg_id failed,%d\n", ret);
		return ret;
	}
	strcpy(g_ismg_node->desc.ismg_id, value);

	ret = com_cfg_get_value(filename, "ip", value);
	if(ret != 0){
		log_printf("read_ismg_conf ip failed,%d\n", ret);
		return ret;
	}
	strcpy(g_ismg_node->desc.ip, value);

	ret = com_cfg_get_value(filename, "port", value);
	if(ret != 0){
		log_printf("read_ismg_conf port failed,%d\n", ret);
		return ret;
	}
	g_ismg_node->desc.port = (ushort)atoi(value);

	ret = com_cfg_get_value(filename, "protocol", value);
	if(ret != 0){
		log_printf("read_ismg_conf protocol failed,%d\n", ret);
		return ret;
	}
	g_ismg_node->desc.protocol = 0x20;

	ret = com_cfg_get_value(filename, "max_rsmg", value);
	if(ret != 0){
		log_printf("read_ismg_conf max_rsmg failed,%d\n", ret);
		return ret;
	}
	g_ismg_node->desc.max_rsmg = atoi(value);

	print_ismg_desc(&g_ismg_node->desc);
	return 0;
}

int read_rsmg_conf(char *filename)
{
	int     ret, i, id;
	char    value[256];
	char    *tok;

	for(i=0; i<G_RSMG_NUM_MAX; i++)
		g_rsmg_node[i] = NULL;
	i = 0;
	while(++i){
		ret = com_cfg_get_row(filename, i, value);
		if(ret != 0)
			break;
		tok = strtok(value, ",");
		id = atoi(tok);
		if(id >= G_RSMG_NUM_MAX)
			continue;
		//g_rsmg_node[id] = calloc(1, sizeof(rsmg_node));
		ret = com_mmap_create((void**)&g_rsmg_node[i], sizeof(rsmg_node));
		if(ret != 0){
			log_error(com_mmap_create, ret);
			return ret;
		}
		g_rsmg_node[id]->desc.idx = id;
//smg_id,ip,port,protocol,send_pwd,recv_pwd,send_links,recv_links,window,timeout,times
		tok = strtok(NULL, ",");
		strcpy(g_rsmg_node[id]->desc.rsmg_id, com_str_trim(tok));

		tok = strtok(NULL, ",");
		strcpy(g_rsmg_node[id]->desc.ip, com_str_trim(tok));

		tok = strtok(NULL, ",");
		g_rsmg_node[id]->desc.port = (ushort)atoi(tok);

		tok = strtok(NULL, ",");
		g_rsmg_node[id]->desc.protocol = 0x20;

		tok = strtok(NULL, ",");
		strcpy(g_rsmg_node[id]->desc.send_pwd, com_str_trim(tok));

		tok = strtok(NULL, ",");
		strcpy(g_rsmg_node[id]->desc.recv_pwd, com_str_trim(tok));

		tok = strtok(NULL, ",");
		g_rsmg_node[id]->desc.send_links = atoi(tok);

		tok = strtok(NULL, ",");
		g_rsmg_node[id]->desc.recv_links = atoi(tok);

		tok = strtok(NULL, ",");
		g_rsmg_node[id]->desc.window = atoi(tok);

		tok = strtok(NULL, ",");
		g_rsmg_node[id]->desc.timeout = atoi(tok);

		tok = strtok(NULL, ",");
		g_rsmg_node[id]->desc.times = atoi(tok);

		print_rsmg_desc(&g_rsmg_node[i]->desc);
	}
	return 0;
}

int read_db_conf(char *filename)
{
	int     ret;
	char    value[256];

	g_db_node = calloc(1, sizeof(db_node));

	ret = com_cfg_get_value(filename, "ip", value);
	if(ret != 0){
		log_printf("read_db_conf failed, ip:%d", ret);
		return ret;
	}
	strcpy(g_db_node->desc.ip, value);

	ret = com_cfg_get_value(filename, "port", value);
	if(ret != 0){
		log_printf("read_db_conf failed, port:%d", ret);
		return ret;
	}
	g_db_node->desc.port = (ushort)atoi(value);

	ret = com_cfg_get_value(filename, "database", value);
	if(ret != 0){
		log_printf("read_db_conf failed, user:%d", ret);
		return ret;
	}
	strcpy(g_db_node->desc.database, value);

	ret = com_cfg_get_value(filename, "user", value);
	if(ret != 0){
		log_printf("read_db_conf failed, user:%d", ret);
		return ret;
	}
	strcpy(g_db_node->desc.user, value);

	ret = com_cfg_get_value(filename, "pwd", value);
	if(ret != 0){
		log_printf("read_db_conf failed, pwd:%d", ret);
		return ret;
	}
	strcpy(g_db_node->desc.pwd, value);

	ret = com_cfg_get_value(filename, "interval", value);
	if(ret != 0){
		log_printf("read_db_conf failed, interval:%d", ret);
		return ret;
	}
	g_db_node->desc.interval = atoi(value);

	ret = com_cfg_get_value(filename, "limit", value);
	if(ret != 0){
		log_printf("read_db_conf failed, limit:%d", ret);
		return ret;
	}
	g_db_node->desc.limit = atoi(value);

	print_db_desc(&g_db_node->desc);
	return 0;
}

void print_ismg_desc(ismg_desc *desc)
{
	log_printf("ismg_id:%s,ip:%s,port:%u,protocol:%#x,max_rsmg:%u", desc->ismg_id, desc->ip, desc->port, desc->protocol, desc->max_rsmg);
}

void print_rsmg_desc(rsmg_desc *desc)
{
	log_printf("idx:%u,rsmg_id:%s,ip:%s,port:%u,protocol:%#x,send_pwd:%s,recv_pwd:%s,send_links:%u,recv_links:%u,window:%u,timeout:%u,times:%u", desc->idx, desc->rsmg_id, desc->ip, desc->port, desc->protocol, desc->send_pwd, desc->recv_pwd, desc->send_links, desc->recv_links, desc->window, desc->timeout, desc->times);
}

void print_db_desc(db_desc *desc)
{
	log_printf("ip:%s,port:%u,database:%s,user:%s,pwd:%s,interval:%u,limit:%u", desc->ip, desc->port, desc->database, desc->user, desc->pwd, desc->interval, desc->limit);
}
