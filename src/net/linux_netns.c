//linux_netns.c
 
/* SPDX-License-Identifier: GPL-2.0 */
#define _ATFILE_SOURCE
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

#include <uthash/utlist.h>
#include "sim/sim.h"
#include "topology.h"

#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <sys/types.h>
#include <linux/if_tun.h>
#include<stdlib.h>
#include<stdio.h>
#include "linux_netns.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/if_tun.h>

#include"host.h"
#define _GNU_SOURCE
int unshare(int flags);
 
struct rtnl_handle rth = { .fd = -1 };
int rcvbuf = 1024 * 1024;
 
int
rtnl_open_netns(char *nsname)
{
  int fd = -1;
  char path[100] = {0};
 
  if (!nsname || !strlen(nsname)) {
    sprintf(path, "%s", "/proc/1/ns/net");
  } else if (strpbrk(nsname, "/") != NULL) {
    sprintf(path, "%s", nsname);
  } else {
    sprintf(path, "/var/run/netns/%s", nsname);
  }
 
  if ((fd = open(path, O_RDONLY)) < 0) {
    fprintf(stderr, "open stream %s: ", path);
 
    return -1;
  }
 
 
  return fd;
}
 
static int netns_get_fd(char *name)
{         
	char nsname = 0;
	if (strcmp(name, "default") == 0){  
          return rtnl_open_netns(&nsname);	 
	}else{    
          return rtnl_open_netns(name);	  
	}
}	
 
/* No extended error ack without libmnl */
static int nl_dump_ext_ack(const struct nlmsghdr *nlh, nl_ext_ack_fn_t errfn)
{
	return 0;
}
 
static int addattr_l(struct nlmsghdr *n, int maxlen, int type, const void *data,
	      int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;
 
	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		fprintf(stderr,
			"addattr_l ERROR: message exceeded bound of %d\n",
			maxlen);
		return -1;
	}
	rta = NLMSG_TAIL(n);
	rta->rta_type = type;
	rta->rta_len = len;
	if (alen)
		memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
	return 0;
}
 
static void rtnl_talk_error(struct nlmsghdr *h, struct nlmsgerr *err,
			    nl_ext_ack_fn_t errfn)
{
	if (nl_dump_ext_ack(h, errfn))
		return;
 
	fprintf(stderr, "RTNETLINK answers: %s\n",
		strerror(-err->error));
}
 
 
static int __rtnl_recvmsg(int fd, struct msghdr *msg, int flags)
{
	int len;
 
	do {
		len = recvmsg(fd, msg, flags);
	} while (len < 0 && (errno == EINTR || errno == EAGAIN));
 
	if (len < 0) {
		fprintf(stderr, "netlink receive error %s (%d)\n",
			strerror(errno), errno);
		return -errno;
	}
 
	if (len == 0) {
		fprintf(stderr, "EOF on netlink\n");
		return -ENODATA;
	}
 
	return len;
}
 
static int rtnl_recvmsg(int fd, struct msghdr *msg, char **answer)
{
	struct iovec *iov = msg->msg_iov;
	char *buf;
	int len;
 
	iov->iov_base = NULL;
	iov->iov_len = 0;
 
	len = __rtnl_recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
	if (len < 0)
		return len;
 
	buf = malloc(len);
	if (!buf) {
		fprintf(stderr, "malloc error: not enough buffer\n");
		return -ENOMEM;
	}
 
	iov->iov_base = buf;
	iov->iov_len = len;
 
	len = __rtnl_recvmsg(fd, msg, 0);
	if (len < 0) {
		free(buf);
		return len;
	}
 
	if (answer)
		*answer = buf;
	else
		free(buf);
 
	return len;
}
 
static int __rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
		       struct nlmsghdr **answer,
		       bool show_rtnl_err, nl_ext_ack_fn_t errfn)
{
	int status;
	unsigned int seq;
	struct nlmsghdr *h;
	struct sockaddr_nl nladdr = { .nl_family = AF_NETLINK };
	struct iovec iov = {
		.iov_base = n,
		.iov_len = n->nlmsg_len
	};
	struct msghdr msg = {
		.msg_name = &nladdr,
		.msg_namelen = sizeof(nladdr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
	};
	char *buf;
 
	n->nlmsg_seq = seq = ++rtnl->seq;
 
	if (answer == NULL)
		n->nlmsg_flags |= NLM_F_ACK;
 
	status = sendmsg(rtnl->fd, &msg, 0);
	if (status < 0) {
		perror("Cannot talk to rtnetlink");
		return -1;
	}
 
	while (1) {
		status = rtnl_recvmsg(rtnl->fd, &msg, &buf);
 
		if (status < 0)
			return status;
 
		if (msg.msg_namelen != sizeof(nladdr)) {
			fprintf(stderr,
				"sender address length == %d\n",
				msg.msg_namelen);
			exit(1);
		}
		for (h = (struct nlmsghdr *)buf; status >= sizeof(*h); ) {
			int len = h->nlmsg_len;
			int l = len - sizeof(*h);
 
			if (l < 0 || len > status) {
				if (msg.msg_flags & MSG_TRUNC) {
					fprintf(stderr, "Truncated message\n");
					free(buf);
					return -1;
				}
				fprintf(stderr,
					"!!!malformed message: len=%d\n",
					len);
				exit(1);
			}
 
			if (nladdr.nl_pid != 0 ||
			    h->nlmsg_pid != rtnl->local.nl_pid ||
			    h->nlmsg_seq != seq) {
				/* Don't forget to skip that message. */
				status -= NLMSG_ALIGN(len);
				h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
				continue;
			}
 
			if (h->nlmsg_type == NLMSG_ERROR) {
				struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
 
				if (l < sizeof(struct nlmsgerr)) {
					fprintf(stderr, "ERROR truncated\n");
				} else if (!err->error) {
					/* check messages from kernel */
					nl_dump_ext_ack(h, errfn);
 
					if (answer)
						*answer = (struct nlmsghdr *)buf;
					else
						free(buf);
					return 0;
				}
 
				if (rtnl->proto != NETLINK_SOCK_DIAG &&
				    show_rtnl_err)
					rtnl_talk_error(h, err, errfn);
 
				errno = -err->error;
				free(buf);
				return -1;
			}
 
			if (answer) {
				*answer = (struct nlmsghdr *)buf;
				return 0;
			}
 
			fprintf(stderr, "Unexpected reply!!!\n");
 
			status -= NLMSG_ALIGN(len);
			h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
		}
		free(buf);
 
		if (msg.msg_flags & MSG_TRUNC) {
			fprintf(stderr, "Message truncated\n");
			continue;
		}
 
		if (status) {
			fprintf(stderr, "!!!Remnant of size %d\n", status);
			exit(1);
		}
	}
}
 
static int rtnl_talk(struct rtnl_handle *rtnl, struct nlmsghdr *n,
	      struct nlmsghdr **answer)
{
	return __rtnl_talk(rtnl, n, answer, true, NULL);
}
 
 
static int rtnl_open_byproto(struct rtnl_handle *rth, unsigned int subscriptions,
		      int protocol)
{
	socklen_t addr_len;
	int sndbuf = 32768;
	int one = 1;
 
	memset(rth, 0, sizeof(*rth));
 
	rth->proto = protocol;
	rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, protocol);
	if (rth->fd < 0) {
		perror("Cannot open netlink socket");
		return -1;
	}
 
	if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
		       &sndbuf, sizeof(sndbuf)) < 0) {
		perror("SO_SNDBUF");
		return -1;
	}
 
	if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
		       &rcvbuf, sizeof(rcvbuf)) < 0) {
		perror("SO_RCVBUF");
		return -1;
	}
 
	/* Older kernels may no support extended ACK reporting */
	setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK,
		   &one, sizeof(one));
 
	memset(&rth->local, 0, sizeof(rth->local));
	rth->local.nl_family = AF_NETLINK;
	rth->local.nl_groups = subscriptions;
 
	if (bind(rth->fd, (struct sockaddr *)&rth->local,
		 sizeof(rth->local)) < 0) {
		perror("Cannot bind netlink socket");
		return -1;
	}
	addr_len = sizeof(rth->local);
	if (getsockname(rth->fd, (struct sockaddr *)&rth->local,
			&addr_len) < 0) {
		perror("Cannot getsockname");
		return -1;
	}
	if (addr_len != sizeof(rth->local)) {
		fprintf(stderr, "Wrong address length %d\n", addr_len);
		return -1;
	}
	if (rth->local.nl_family != AF_NETLINK) {
		fprintf(stderr, "Wrong address family %d\n",
			rth->local.nl_family);
		return -1;
	}
	rth->seq = time(NULL);
	return 0;
}
 
static int rtnl_open(struct rtnl_handle *rth, unsigned int subscriptions)
{
	return rtnl_open_byproto(rth, subscriptions, NETLINK_ROUTE);
}
 
static void rtnl_close(struct rtnl_handle *rth)
{
	if (rth->fd >= 0) {
		close(rth->fd);
		rth->fd = -1;
	}
}
 
int iplink_set_if_to_ns(int if_index, char * nsname)
{
    int netns = -1;
 
	struct iplink_req req = {
		.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg)),
		.n.nlmsg_flags = NLM_F_REQUEST | 0,
		.n.nlmsg_type = RTM_NEWLINK,
		.i.ifi_family = AF_UNSPEC,
	};
 
    if (rtnl_open(&rth, 0) < 0)
		return -1;
 
    netns = netns_get_fd(nsname);
	if (netns >= 0)
		addattr_l(&req.n, sizeof(req), IFLA_NET_NS_FD,
				&netns, 4);
	else
		fprintf(stderr, "Cannot find netns \"%s\"\n", nsname);
 
 
	req.i.ifi_index = if_index;
 
	if (rtnl_talk(&rth, &req.n, NULL) < 0)
		return -2;
 
        close(netns);
        rtnl_close(&rth);
	return 0;
}
 
 
/****************************************ns add/del*/
static int on_netns_del(char *nsname)
{
	char netns_path[PATH_MAX];
 
	snprintf(netns_path, sizeof(netns_path), "%s/%s", NETNS_RUN_DIR, nsname);
	umount2(netns_path, MNT_DETACH);
	if (unlink(netns_path) < 0) {
		fprintf(stderr, "Cannot remove namespace file \"%s\": %s\n",
			netns_path, strerror(errno));
		return -1;
	}
	return 0;
}
 
int netns_delete(char *nsname)
{
	if (nsname == NULL) {
		fprintf(stderr, "No netns name specified\n");
		return -1;
	}
 
	return on_netns_del(nsname);
}
 
static int create_netns_dir(void)
{
	/* Create the base netns directory if it doesn't exist */
	if (mkdir(NETNS_RUN_DIR, S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH)) {
		if (errno != EEXIST) {
			fprintf(stderr, "mkdir %s failed: %s\n",
				NETNS_RUN_DIR, strerror(errno));
			return -1;
		}
	}
 
	return 0;
}
 
int netns_add(char *nsname)
{
	/* This function creates a new network namespace and
	 * a new mount namespace and bind them into a well known
	 * location in the filesystem based on the name provided.
	 *
	 * The mount namespace is created so that any necessary
	 * userspace tweaks like remounting /sys, or bind mounting
	 * a new /etc/resolv.conf can be shared between uers.
	 */
	char netns_path[PATH_MAX];
	char *name;
	int fd;
	int made_netns_run_dir_mount = 0;
 
	if (nsname == NULL) {
		fprintf(stderr, "No netns name specified\n");
		return -1;
	}
	name = nsname;
 
	snprintf(netns_path, sizeof(netns_path), "%s/%s", NETNS_RUN_DIR, name);
 
	if (create_netns_dir())
		return -1;
 
	/* Make it possible for network namespace mounts to propagate between
	 * mount namespaces.  This makes it likely that a unmounting a network
	 * namespace file in one namespace will unmount the network namespace
	 * file in all namespaces allowing the network namespace to be freed
	 * sooner.
	 */
	while (mount("", NETNS_RUN_DIR, "none", MS_SHARED | MS_REC, NULL)) {
		/* Fail unless we need to make the mount point */
		if (errno != EINVAL || made_netns_run_dir_mount) {
			fprintf(stderr, "mount --make-shared %s failed: %s\n",
				NETNS_RUN_DIR, strerror(errno));
			return -1;
		}
 
		/* Upgrade NETNS_RUN_DIR to a mount point */
		if (mount(NETNS_RUN_DIR, NETNS_RUN_DIR, "none", MS_BIND | MS_REC, NULL)) {
			fprintf(stderr, "mount --bind %s %s failed: %s\n",
				NETNS_RUN_DIR, NETNS_RUN_DIR, strerror(errno));
			return -1;
		}
		made_netns_run_dir_mount = 1;
	}
 
	/* Create the filesystem state */
	fd = open(netns_path, O_RDONLY|O_CREAT|O_EXCL, 0);
	if (fd < 0) {
		fprintf(stderr, "Cannot create namespace file \"%s\": %s\n",
			netns_path, strerror(errno));
		return -1;
	}
 
	close(fd);
	if (unshare(CLONE_NEWNET) < 0) {
		fprintf(stderr, "Failed to create a new network namespace \"%s\": %s\n",
			name, strerror(errno));
		goto out_delete;
	}
 
	/* Bind the netns last so I can watch for it */
	if (mount("/proc/self/ns/net", netns_path, "none", MS_BIND, NULL) < 0) {
		fprintf(stderr, "Bind /proc/self/ns/net -> %s failed: %s\n",
			netns_path, strerror(errno));
		goto out_delete;
	}
	return 0;
out_delete:
	netns_delete(name);
	return -1;
}
 
int netns_switch(char *name)
{
	int netns;
        netns = netns_get_fd(name);
        if (netns < 0) {
                fprintf(stderr, "Cannot open network namespace \"%s\": %s\n",
                        name, strerror(errno));
                return -1;
        }
 
        if (setns(netns, CLONE_NEWNET) < 0) {
                fprintf(stderr, "setting the network namespace \"%s\" failed: %s\n",
                        name, strerror(errno));
                close(netns);
                return -1;
        }
 
        close(netns);
	return 0;
}

int tun_alloc(char *dev, int flags)
{

    struct ifreq ifr;
    int fd, err;
    char *clonedev = "/dev/net/tun";

    if ((fd = open(clonedev, O_RDWR)) < 0) {
        return fd;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = flags;

	if (*dev != '\0')
    {
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    }
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        close(fd);
        return err;
    }

    printf("Open tun/tap device: %s for reading...\n", ifr.ifr_name);

	// 一旦设备开启成功，系统会给设备分配一个名称，对于tun设备，一般为tunX，X为从0开始的编号
	strcpy(dev, ifr.ifr_name);

    return fd;
}
int tap_set_mac(const unsigned char *interface_name, const unsigned char *str_macaddr)    
{  
    int             ret;    
    int             sock_fd;    
    struct ifreq    ifr;        
    unsigned int    mac2bit[6];  
 
    if(interface_name == NULL || str_macaddr == NULL)  
    {  
        return -1;  
    }  
 
    //提取mac格式   
    sscanf((char *)str_macaddr, "%02X:%02X:%02X:%02X:%02X:%02X", 
            (unsigned int *)&mac2bit[0], (unsigned int *)&mac2bit[1], 
            (unsigned int *)&mac2bit[2], (unsigned int *)&mac2bit[3], 
            (unsigned int *)&mac2bit[4], (unsigned int *)&mac2bit[5]);
 
    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);    
    if (sock_fd < 0)    
    {            
        return -2;    
    }    
      
    sprintf(ifr.ifr_ifrn.ifrn_name, "%s", interface_name);    
    ifr.ifr_ifru.ifru_hwaddr.sa_family = 1;    
    ifr.ifr_ifru.ifru_hwaddr.sa_data[0] = mac2bit[0];  
    ifr.ifr_ifru.ifru_hwaddr.sa_data[1] = mac2bit[1];  
    ifr.ifr_ifru.ifru_hwaddr.sa_data[2] = mac2bit[2];  
    ifr.ifr_ifru.ifru_hwaddr.sa_data[3] = mac2bit[3];  
    ifr.ifr_ifru.ifru_hwaddr.sa_data[4] = mac2bit[4];  
    ifr.ifr_ifru.ifru_hwaddr.sa_data[5] = mac2bit[5];  
      
    ret = ioctl(sock_fd, SIOCSIFHWADDR, &ifr);    
    if (ret != 0)    
    {    
        return -4;    
    }          
    close(sock_fd);
    return 0;    
}
 
int tap_set_ip(const unsigned char *interface_name, const unsigned char *ipaddr)    
{  
    int err;
	int             ret;    
    int             socket_fd;    
    struct ifreq    ifr;        
    struct sockaddr_in sin;
    
    if(interface_name == NULL || ipaddr == NULL)  
    {  
        return -1;  
    }  
    
    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0)    
    {
        printf("Create Socket Failed.\n");        
        return -2;    
    }
    //指定网卡名称且up
    sprintf(ifr.ifr_name, "%s", interface_name);
	/* 获得接口的标志 */
    if ((err = ioctl(socket_fd, SIOCGIFFLAGS, (void *)&ifr)) < 0) {
        perror("ioctl SIOCGIFADDR");
		close(socket_fd);
        return -3;
    }
    ifr.ifr_flags |= IFF_UP;
    ret = ioctl(socket_fd, SIOCSIFFLAGS, &ifr);
    if (ret != 0)    
    {
        printf("Up Device %s Failed.\n", interface_name);
        close(socket_fd);
        return -3;
    }
    //设置ip
    memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET; 
    inet_pton(AF_INET, ipaddr, &sin.sin_addr.s_addr);
    memcpy(&ifr.ifr_addr, &sin, sizeof(struct sockaddr));
    ret = ioctl(socket_fd, SIOCSIFADDR, &ifr);
	if (ret != 0)    
    {    
        printf("Set Ipaddr For Device %s Failed.\n", interface_name);
        close(socket_fd);
        return -4;    
    }
	
    //设置mask
	sin.sin_family = AF_INET;
    inet_pton(AF_INET, "255.255.255.0", &sin.sin_addr.s_addr);
    memcpy(&ifr.ifr_netmask, &sin, sizeof(struct sockaddr));
    ret = ioctl(socket_fd, SIOCSIFNETMASK, &ifr);
	
    if (ret != 0)    
    {    
        printf("Set NetMask For Device %s Failed.\n", interface_name);
        close(socket_fd);
        return -5;    
    }          
    close(socket_fd);
    return 0;    
}

void uint32ToChar(uint32_t ip_t,char *cc)
{
	char ipChar[32];
	uint32_t index = 0;
	memset(ipChar,0,sizeof(ipChar));
	
	printf("%d\n\n\n",strlen(cc));
	for(uint32_t i = 3; i>=0 && i <= 3; --i)
	{
		uint32_t temp = ip_t;
		
		for(uint32_t j = 0; j<i; ++j)
			temp /= 256;
		
		
		
		uint32_t t[3];
		t[0] = temp / 100;
		t[1] = ( temp - t[0] * 100 ) / 10;
		t[2] = ( temp - t[0] * 100 - t[1] * 10);
		
		if((t[0] | t[1] | t[2]) == 0)
			ipChar[index++] = '0';
		else
		{
			for(uint32_t j = 0; j<3; ++j)
			{
				if(t[j] != 0)
				{
					for(uint32_t k = j; k<3; ++k)
						ipChar[index++] = t[k] + '0';
					break;
				}
			}
		}
		
		for(uint32_t j = 0; j<i; ++j)
			temp *= 256;
		ip_t -= temp;

		if(i != 0)
			ipChar[index++] = '.';
		
	}
	//printf("%s\n\n",ipChar);
	//for(int j = 0; j<index; ++j)
		//printf("%c",ipChar[j]);
	//printf("\n");
	ipChar[index] = '\0';
	strcpy(cc,ipChar);
	//printf("%s\n\n",ipChar);
	return;
}
/*
void MOnitorAllHost(struct scheduler *sch,int fd_r;int fd_w,struct node* h)
{	
	//find all host;
	uint32_t ip_host = ip_t;
	uint32_t ip_dst = 0;
	
	char s[1];
	
	while(read(fd_r, s, 1)
	{
		printf("this is f,we read child\n");
		
	}
	
}*/





