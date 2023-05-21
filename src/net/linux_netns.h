//linux_netns.h
 
#ifndef LINUX_NETNS_H_
#define LINUX_NETNS_H_
 
#include <linux/kernel.h>
#include <linux/socket.h> /* for __kernel_sa_family_t */
#include <linux/types.h>
 
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <sched.h>
#include <sys/mount.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
 #include "sim/sim.h"
 #include "topology.h"
#include "topology.h"
 
#define NETNS_RUN_DIR "/var/run/netns"
#define DEFAULT_NETNS_RUN_DIR "/proc/self/ns/net"
#define NETNS_ETC_DIR "/etc/netns"
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000	/* New network namespace (lo, device, names sockets, etc) */
#endif
 
#define NLMSG_ALIGNTO	4U
#define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
#define NLMSG_HDRLEN	 ((int) NLMSG_ALIGN(sizeof(struct nlmsghdr)))
#define NLMSG_LENGTH(len) ((len) + NLMSG_HDRLEN)
 
#define NLM_F_REQUEST		0x01	/* It is request message. 	*/
 
/* Macros to handle rtattributes */
 
#define RTA_ALIGNTO	4U
#define RTA_ALIGN(len) ( ((len)+RTA_ALIGNTO-1) & ~(RTA_ALIGNTO-1) )
#define RTA_OK(rta,len) ((len) >= (int)sizeof(struct rtattr) && \
			 (rta)->rta_len >= sizeof(struct rtattr) && \
			 (rta)->rta_len <= (len))
#define RTA_NEXT(rta,attrlen)	((attrlen) -= RTA_ALIGN((rta)->rta_len), \
				 (struct rtattr*)(((char*)(rta)) + RTA_ALIGN((rta)->rta_len)))
#define RTA_LENGTH(len)	(RTA_ALIGN(sizeof(struct rtattr)) + (len))
#define RTA_SPACE(len)	RTA_ALIGN(RTA_LENGTH(len))
#define RTA_DATA(rta)   ((void*)(((char*)(rta)) + RTA_LENGTH(0)))
#define RTA_PAYLOAD(rta) ((int)((rta)->rta_len) - RTA_LENGTH(0))
 
#define NLMSG_TAIL(nmsg) \
	((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))
 
/* Flags values */
 
#define NLM_F_REQUEST		0x01	/* It is request message. 	*/
#define NLM_F_MULTI		0x02	/* Multipart message, terminated by NLMSG_DONE */
#define NLM_F_ACK		0x04	/* Reply with ack, with zero or error code */
#define NLM_F_ECHO		0x08	/* Echo this request 		*/
#define NLM_F_DUMP_INTR		0x10	/* Dump was inconsistent due to sequence change */
#define NLM_F_DUMP_FILTERED	0x20	/* Dump was filtered as requested */
 
#define NETLINK_SOCK_DIAG	4	/* socket monitoring				*/
 
struct rtnl_handle {
	int			fd;
	struct sockaddr_nl	local;
	struct sockaddr_nl	peer;
	__u32			seq;
	__u32			dump;
	int			proto;
	FILE		       *dump_fp;
#define RTNL_HANDLE_F_LISTEN_ALL_NSID		0x01
#define RTNL_HANDLE_F_SUPPRESS_NLERR		0x02
	int			flags;
};
 
#ifndef CLONE_NEWNET
#define CLONE_NEWNET 0x40000000	/* New network namespace (lo, device, names sockets, etc) */
#endif
 
#ifndef MNT_DETACH
#define MNT_DETACH	0x00000002	/* Just detach from the tree */
#endif /* MNT_DETACH */
 
/* sys/mount.h may be out too old to have these */
#ifndef MS_REC
#define MS_REC		16384
#endif
 
#ifndef MS_SLAVE
#define MS_SLAVE	(1 << 19)
#endif
 
#ifndef MS_SHARED
#define MS_SHARED	(1 << 20)
#endif
 
#if 0
#ifndef HAVE_SETNS
static inline int setns(int fd, int nstype)
{
#ifdef __NR_setns
	return syscall(__NR_setns, fd, nstype);
#else
	errno = ENOSYS;
	return -1;
#endif
}
#endif /* HAVE_SETNS */
#endif
 
 
struct iplink_req {
	struct nlmsghdr		n;
	struct ifinfomsg	i;
	char			buf[1024];
};
 
typedef int (*nl_ext_ack_fn_t)(const char *errmsg, __u32 off,
			       const struct nlmsghdr *inner_nlh);
// void momo(struct sim *s);
int netns_add(char *nsname);
int netns_delete(char *nsname);
int iplink_set_if_to_ns(int if_index, char * nsname);
 
int tun_alloc(char *dev, int flags);
 
int netns_switch(char *netns);
int rtnl_open_netns(char *nsname);

int tap_set_mac(const unsigned char *interface_name, const unsigned char *str_macaddr);
int tap_set_ip(const unsigned char *interface_name, const unsigned char *ipaddr);
void uint32ToChar(uint32_t ip_t,char* cc);

#endif /*LINUX_NETNS_H_*/
