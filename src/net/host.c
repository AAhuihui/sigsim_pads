#include "host.h"
#include "legacy_node.h"
#include "route_table.h"
#include "arp_table.h"
#include "lib/util.h"
#include <log/log.h>
#include <uthash/utlist.h>

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include<stdlib.h>
#include<stdio.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/inotify.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <sched.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <linux/limits.h>
#include <stdbool.h>
#include <linux/net_namespace.h>
#include "linux_netns.h"
#include <stdlib.h>
#include <threads.h>

#include "sim/scheduler.h"
#define ETH_ADDR_FMT                                                    \
    "%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8":%02"PRIx8
#define ETH_ADDR_ARGS(ea)                                   \
    (ea)[0], (ea)[1], (ea)[2], (ea)[3], (ea)[4], (ea)[5]

struct host {
    struct legacy_node ep; /* Node is an endpoint */
    struct app *apps;      /* Hash Map of applications */
    struct exec *execs;    /* List of apps to be executed */
    struct scheduler *sch;
    uint32_t ip_t;
    char nsName[32];
};

void UpSch(struct host * h,struct scheduler *sch)
{
	h->sch = sch;
}

struct host *
host_new(char *nsName)
{
    struct host *h = xmalloc(sizeof(struct host));
    legacy_node_init(&h->ep, HOST);
    h->ep.base.recv_netflow = host_recv_netflow;
    h->ep.base.send_netflow = host_send_netflow;
    h->apps = NULL;
    h->execs = NULL;
    
    h->ip_t = 0;
    strcpy(h->nsName,nsName);
    //host_add_monitor_ns(h,nsName);
    return h;
}

void 
host_destroy(struct host *h)
{
    struct exec *exec, *exec_tmp;
    struct app *app, *app_tmp;
    legacy_node_clean(&h->ep);
    
    HASH_ITER(hh, h->apps, app, app_tmp) {
        HASH_DEL(h->apps, app);
        app_destroy(app);
    }
    HASH_ITER(hh, h->execs, exec, exec_tmp) {
        HASH_DEL(h->execs, exec);
        app_destroy_exec(exec);
    }
    free(h);
}

void 
host_add_port(struct host *h, uint32_t port_id, 
              uint8_t eth_addr[ETH_LEN], uint32_t speed, 
              uint32_t curr_speed)
{   
    node_add_port( (struct node*) h, port_id, eth_addr, speed, curr_speed);
}

void
host_set_intf_ipv4(struct host *h, uint32_t port_id, 
                   uint32_t addr, uint32_t netmask){
        if(addr != 0)
	{
		h->ip_t = addr;
    		//host_add_monitor_ns(h);
    		thrd_t th;
    		thrd_create(&th, host_add_monitor_ns,(void*)h);
	}
    legacy_node_set_intf_ipv4(&h->ep, port_id, addr, netmask);   
}

struct netflow*
host_recv_netflow(struct node *n, struct netflow *flow)
{
    struct host *h = (struct host*) n;
    /* Check MAC and IP addresses. Only returns true if
       both have the node destination MAC and IP       */
    uint16_t eth_type = flow->match.eth_type;
    struct netflow* nf = l2_recv_netflow(&h->ep, flow); 
    
    if (eth_type == ETH_TYPE_IP || eth_type == ETH_TYPE_IPV6) {
        if (l3_recv_netflow(&h->ep, nf)){
            struct app *app;
            uint16_t ip_proto = flow->match.ip_proto;
            HASH_FIND(hh, h->apps, &ip_proto, sizeof(uint16_t), app);
            /* If gets here send to application */
            log_debug("APP %d %p", ip_proto, app);
            if (app){
                if (app->handle_netflow(nf)){
                    return find_forwarding_ports(&h->ep, nf);
                }
            } 
        }
    }
    else if (eth_type == ETH_TYPE_ARP){
        /* End here if there is not further processing */
        return nf;
    }
    return NULL;
}

void 
host_send_netflow(struct node *n, struct netflow *flow, uint32_t out_port)
{
    node_update_port_stats(n, flow, out_port);
}

void 
host_add_app(struct host *h, uint16_t type)
{
    struct app *a =  app_creator(type);
    HASH_ADD(hh, h->apps, type, sizeof(uint16_t), a);
}

void 
host_add_app_exec(struct host *h, uint64_t id, uint32_t type,
                  uint32_t execs_num, uint64_t start_time, void *args, 
                  size_t arg_size)
{
    struct app *app = NULL;
    /* Guarantees the app can be executed */
    HASH_FIND(hh, h->apps, &type, sizeof(uint16_t), app);
    if (app) {
        struct exec *exec = app_new_exec(id, type, execs_num, start_time, 
                                         args, arg_size);
        HASH_ADD(hh, h->execs, id, sizeof(uint64_t), exec);
    }
}

struct netflow* 
host_execute_app(struct host *h, struct exec *exec)
{
    struct app *app;
    HASH_FIND(hh, h->apps, &exec->type, sizeof(uint16_t), app);
    struct netflow *flow = NULL;
    /* If app still has remaining executions */
    if (app) {
        flow = app->start(exec->start_time, exec->args);
        flow->exec_id = exec->id;
        log_info("Flow Start time APP %ld", flow-> start_time);
        exec->exec_cnt -= 1;
        return find_forwarding_ports(&h->ep, flow);
    }
    return NULL;
}

void host_set_name(struct host* h, char *name)
{
    memcpy(h->ep.base.name, name, MAX_NODE_NAME);
}

/* Access functions*/
char *host_name(struct host *h)
{
    return h->ep.base.name;
}

/* Retrieve a datapath port */
struct port* 
host_port(const struct host *h, uint32_t port_id)
{
    struct port *p = node_port( (struct node*) h, port_id);
    return p;
}

uint64_t 
host_uuid(const struct host* h)
{
    return h->ep.base.uuid;
}

struct app *host_apps(const struct host *h)
{
    return h->apps;
}

struct exec *host_execs(const struct host *h)
{
    return h->execs;
}

void
host_add_monitor_ns(void* arg)
{	
	struct host *h = (struct host*)arg;
	char *nsName = h->nsName;
	printf("%s\n",nsName);
	// create process_child	
	//pipe(h->fd1);
	//pipe(h->fd2);
	
	//if(fork() != 0)
		//return;
	uint32_t ip_t = h->ip_t;
	
	printf("%d\n",ip_t);
	
	char cc[32];
	memset(cc,0,sizeof(cc));
	
	uint32ToChar(ip_t,cc);
	printf("%d %s\n",strlen(cc),cc);
	//return;
	//exit(1);
	//return;
	
	//child
	//switch to ns & create tap
	netns_switch(nsName);
	int tun_fd, nread;
    	char buffer[1500];
	char tun_name[IFNAMSIZ];

	tun_name[0] = '\0';

    /* Flags: IFF_TUN   - TUN device (no Ethernet headers)
     *        IFF_TAP   - TAP device
     *        IFF_NO_PI - Do not provide packet information
     */
    	tun_fd = tun_alloc(tun_name, IFF_TUN | IFF_NO_PI);
    	if (tun_fd < 0) {
        perror("Allocating interface");
        exit(1);
    	}
    	
    	tap_set_ip("tun0", cc);
    	//name : tun0
    	//char TapNameDefault[5] = "tun0";
    	//char TapIp = '0';
    	
    	int execid = 2;
    	while(1)
    	{
    		unsigned char ip[4];
    		//read tap & waiting
    		nread = read(tun_fd, buffer, sizeof(buffer));
        	if (nread < 0) {
            		perror("Reading from interface");
            		close(tun_fd);
            		exit(1);
        	}
        	printf("Read %d bytes from tun/tap device\n", nread);
        	
        	/*
        	void 
		host_add_app_exec(struct host *h, uint64_t id, uint32_t type,
                  	uint32_t execs_num, uint64_t start_time, void *args, 
                  	size_t arg_size)
		{
    		struct app *app = NULL;
    		HASH_FIND(hh, h->apps, &type, sizeof(uint16_t), app);
    		if (app) {
        		struct exec *exec = app_new_exec(id, type, execs_num, start_time, 
                                         args, arg_size);
        		HASH_ADD(hh, h->execs, id, sizeof(uint64_t), exec);
    			}
		}
        	*/
        	
        	if(nread == 84 )
        	{
        		uint32_t ipt = 0;
        		for(uint32_t i = 0; i<4; ++i)
			{
				ipt *= 256;
				ipt += buffer[16 + i];
			}//dstip 
        		uint32_t ip1 = ipt; //ip1: dst ip; 
        		//printf("myid:%d,myns:%s,the dstip = %d\n",h->ip_t,h->nsName,ip1);
        		struct exec *exec = app_new_exec(execid++, 1, 1, 2000000 + execid * 1000, (void*) &ip1,sizeof(int));
        		//host_add_app_exec(h,execid++,1,1,2000000 + execid * 1000,(void*) &ip1,sizeof(int));
        		struct sim_event_app_start *ev = sim_event_app_start_new(exec->start_time, h->ep.base.uuid,exec);
            		//scheduler_insert(sch, (struct sim_event*) ev);
            		//printf("ok %d\n",execid-1);
            		//write(fd2[1], "1", 1);
            		//printf("event created success! node_id:%d\n",ev->node_id);
            		struct scheduler *sch  = h->sch;
            		scheduler_insert(sch, (struct sim_event*) ev);
        		
    		}
        		//try : make a event & insert;
        	
        	//host_add_app_exec(h, 2, 1,1, 2000000, (void*) &ip1, sizeof(int));
        	// ping? add_exec & waiting 
        	
        	//my ip : ip_t; dstIp;
        	
        	//success --> fake packet
        	
        	//构造icmp rep包
		memcpy(ip, &buffer[12], 4);
		memcpy(&buffer[12], &buffer[16], 4);
		memcpy(&buffer[16], ip, 4);
		buffer[20] = 0;
		*((unsigned short *)&buffer[22]) += 8;

		//发包
        	nread = write(tun_fd, buffer, nread);
		printf("Write %d bytes to tun/tap device, that's %s\n", nread, buffer);
    	}
}
   
