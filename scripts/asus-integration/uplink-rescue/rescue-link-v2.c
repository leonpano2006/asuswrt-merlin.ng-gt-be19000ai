/* Source-only candidate: review before building or running.
 * Own exactly one labelled IPv4 /32 and one peer route. Never change links,
 * rules, neighbours, normal addresses, sysctls, firewall or ASUS state.
 * Ambiguous writes deliberately retain an intent requiring human review.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/fib_rules.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_arp.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define SELF_IP "169.254.190.15"
#define PEER_IP "169.254.190.51"
#define ETH "eth0"
#define BR "br0"
#define STATE_DIR "/run/leon-asus-rescue-link"
#define ENROLLMENT "/etc/leon/rescue-link-enrollment"
#define PROTO 186
#define METRIC 42760
#define LEON_MAX_LINKS 512
#define MAX_ADDRS 1024
#define MAX_ROUTES 4096
#define MAX_MESSAGES 4096
#define MAX_DUMP_BYTES (1024U*1024U)
#define SNAPSHOT_MS 5000
#define OP_MS 2000
static const unsigned char mac[6]={0x02,0x00,0x00,0xf0,0x00,0x01};
static const char enrollment[]=
 "LEON_UPLINK_RESCUE_V1\nrouter=169.254.190.15/32\npeer=169.254.190.51/32\n"
 "eth0=02:00:00:f0:00:01\nbr0=02:00:00:f0:00:01\n"
 "labels=eth0:lr,br0:lr\nroute=main,186,42760\n";
static uint32_t self_ip,peer_ip,nl_sequence,nl_port;
static int nl=-1,dirfd=-1,lockfd=-1;
static volatile sig_atomic_t stopping;
static char boot_id[37];
static bool eth_enrolled_seen,bridge_enrolled_seen;

struct link {int index,master; unsigned flags; unsigned short type;
 char name[16]; unsigned char mac[6]; bool has_mac,carrier,has_carrier,bridge;};
struct address {int index; uint32_t local,address,flags; unsigned prefix,scope;
 char label[16]; bool has_local,has_address,has_label,broadcast,unknown;};
struct route {uint32_t dst,src,table,oif,pref,metric; unsigned prefix,src_prefix,tos,
 type,scope,protocol,flags; bool has_dst,has_pref,has_metric,gateway,multipath,unknown;};
struct snapshot {struct link links[LEON_MAX_LINKS];struct address addrs[MAX_ADDRS];
 struct route routes[MAX_ROUTES];unsigned links_n,addrs_n,routes_n,rules_mask;};
/* Only ADDR/ACTIVE are stable ownership. Intent states never justify adoption.
 * A crash between an ACK and durable stable receipt may leak an alias, but must
 * not turn a concurrent foreign EEXIST into permission to delete its object. */
enum phase {P_ADDR_INTENT=1,P_ADDR=2,P_ROUTE_INTENT=3,P_ACTIVE=4,
 P_ROUTE_DELETE=5,P_ADDR_DELETE=6};
struct owned {bool present;int index;char name[16];enum phase phase;};

static int64_t now_ms(void){struct timespec t;if(clock_gettime(CLOCK_MONOTONIC,&t))return -1;
 return (int64_t)t.tv_sec*1000+t.tv_nsec/1000000;}
static void stop_handler(int sig){(void)sig;stopping=1;}
static int fail(const char *what){fprintf(stderr,"LEON_RESCUE error=%s errno=%d\n",what,errno);return -1;}
static bool exact_name(const char *s){return !strcmp(s,ETH)||!strcmp(s,BR);}
static const char *label(const char *s){return !strcmp(s,ETH)?"eth0:lr":"br0:lr";}
static int safe_text(const char *path,char *out,size_t cap,mode_t mode){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
 struct stat st;ssize_t n;int e=0;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
    (st.st_mode&07777)!=mode||st.st_size<=0||(uint64_t)st.st_size>=cap)e=EPERM;
 if(!e){n=read(fd,out,cap-1);if(n!=st.st_size)e=EIO;else out[n]=0;}
 close(fd);if(e){errno=e;return -1;}return 0;
}
static int proc_text(const char *path,char *out,size_t cap){
 int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);if(fd<0)return -1;
 ssize_t n=read(fd,out,cap-1);char extra;ssize_t tail=n>=0?read(fd,&extra,1):-1;
 int e=errno;close(fd);if(n<=0||tail!=0){errno=n<0?e:EOVERFLOW;return -1;}out[n]=0;return 0;
}
static int native_ns(void){struct stat a,b,r,s;
 if(geteuid()!=0||stat("/proc/self/ns/net",&a)||stat("/proc/1/ns/net",&b)||
    stat("/",&r)||stat("/proc/1/root",&s)||a.st_dev!=b.st_dev||a.st_ino!=b.st_ino||
    r.st_dev!=s.st_dev||r.st_ino!=s.st_ino){errno=EPERM;return -1;}return 0;
}
static int initialize(void){char text[512];struct stat st;char boot[40];
 if(native_ns()||safe_text(ENROLLMENT,text,sizeof(text),0644)||strcmp(text,enrollment))return fail("enrollment-or-native-namespace");
 if(proc_text("/proc/sys/kernel/random/boot_id",boot,sizeof(boot))||strlen(boot)!=37||boot[36]!='\n')return fail("boot-id");
 for(unsigned i=0;i<36;++i){bool dash=i==8||i==13||i==18||i==23;
  if(dash?boot[i]!='-':!((boot[i]>='0'&&boot[i]<='9')||(boot[i]>='a'&&boot[i]<='f'))){errno=EINVAL;return fail("boot-id-shape");}}
 memcpy(boot_id,boot,36);boot_id[36]=0;
 dirfd=open(STATE_DIR,O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
 if(dirfd<0||fstat(dirfd,&st)||st.st_uid||st.st_gid||(st.st_mode&07777)!=0700)return fail("runtime-directory");
 lockfd=openat(dirfd,"lock",O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW,0600);
 if(lockfd<0||fstat(lockfd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
    (st.st_mode&07777)!=0600||flock(lockfd,LOCK_EX|LOCK_NB))return fail("runtime-lock");
 if(inet_pton(AF_INET,SELF_IP,&self_ip)!=1||inet_pton(AF_INET,PEER_IP,&peer_ip)!=1)return -1;
 nl=socket(AF_NETLINK,SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK,NETLINK_ROUTE);if(nl<0)return fail("netlink-socket");
 struct sockaddr_nl sa={.nl_family=AF_NETLINK};socklen_t sz=sizeof(sa);
 if(bind(nl,(void*)&sa,sizeof(sa))||getsockname(nl,(void*)&sa,&sz)||sz!=sizeof(sa)||!sa.nl_pid)return fail("netlink-bind");
 nl_port=sa.nl_pid;return 0;
}
static int owned_load(struct owned *o){
 memset(o,0,sizeof(*o));int fd=openat(dirfd,"state",O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK);
 if(fd<0)return errno==ENOENT?0:-1;
 struct stat st;char data[256],id[37],name[16],extra,canonical[256];int index,ph;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_gid||st.st_nlink!=1||
    (st.st_mode&07777)!=0600||st.st_size<=0||st.st_size>=(off_t)sizeof(data)){close(fd);errno=EPERM;return -1;}
 ssize_t n=read(fd,data,sizeof(data)-1);close(fd);if(n!=st.st_size){errno=EIO;return -1;}data[n]=0;
 if(sscanf(data,"LEON_RESCUE_V1\nboot=%36[0-9a-f-]\nindex=%d\ndevice=%15[a-z0-9]\nphase=%d\n%c",id,&index,name,&ph,&extra)!=4||
    strcmp(id,boot_id)||index<=0||!exact_name(name)||ph<P_ADDR_INTENT||ph>P_ADDR_DELETE){errno=EPERM;return -1;}
 int k=snprintf(canonical,sizeof(canonical),"LEON_RESCUE_V1\nboot=%s\nindex=%d\ndevice=%s\nphase=%d\n",id,index,name,ph);
 if(k!=n||memcmp(canonical,data,n)){errno=EINVAL;return -1;}
 o->present=true;o->index=index;strcpy(o->name,name);o->phase=ph;return 0;
}
static int owned_save(struct owned *o,enum phase ph){
 char data[256];int n=snprintf(data,sizeof(data),"LEON_RESCUE_V1\nboot=%s\nindex=%d\ndevice=%s\nphase=%d\n",boot_id,o->index,o->name,ph);
 int fd=openat(dirfd,"state.next",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC|O_NOFOLLOW,0600);
 if(fd<0)return -1;
 /* Keep a partial temp on failure. Never overwrite another unfinished intent. */
 if(write(fd,data,n)!=n||fsync(fd)){close(fd);return -1;}if(close(fd))return -1;
 if(renameat(dirfd,"state.next",dirfd,"state")||fsync(dirfd))return -1;
 o->phase=ph;o->present=true;return 0;
}
static int owned_clear(struct owned *o){if(unlinkat(dirfd,"state",0)&&errno!=ENOENT)return -1;
 if(fsync(dirfd))return -1;memset(o,0,sizeof(*o));return 0;}
static bool u32attr(const struct rtattr *a,uint32_t *v){if(RTA_PAYLOAD(a)!=4)return false;memcpy(v,RTA_DATA(a),4);return true;}
static bool stringattr(const struct rtattr *a,char *dst,size_t cap){size_t n=RTA_PAYLOAD(a);
 if(!n||n>cap||((char*)RTA_DATA(a))[n-1]||memchr(RTA_DATA(a),0,n-1))return false;memcpy(dst,RTA_DATA(a),n);return true;}
static int attributes(const struct nlmsghdr *h,size_t base,struct rtattr **a,int *len){
 if(h->nlmsg_len<NLMSG_LENGTH(base)){errno=EPROTO;return -1;}
 *len=h->nlmsg_len-NLMSG_LENGTH(base);*a=(void*)((char*)NLMSG_DATA(h)+NLMSG_ALIGN(base));return 0;
}
static int parse_link(struct snapshot *s,const struct nlmsghdr *h){
 if(s->links_n==LEON_MAX_LINKS)return -1;struct rtattr *a;int len;
 if(attributes(h,sizeof(struct ifinfomsg),&a,&len))return -1;
 const struct ifinfomsg *m=NLMSG_DATA(h);struct link *l=&s->links[s->links_n++];
 l->index=m->ifi_index;l->flags=m->ifi_flags;l->type=m->ifi_type;
 for(;RTA_OK(a,len);a=RTA_NEXT(a,len)){uint32_t v;
  switch(a->rta_type&NLA_TYPE_MASK){case IFLA_IFNAME:if(*l->name||!stringattr(a,l->name,sizeof(l->name)))return -1;break;
   case IFLA_ADDRESS:if(RTA_PAYLOAD(a)==6){memcpy(l->mac,RTA_DATA(a),6);l->has_mac=true;}break;
   case IFLA_MASTER:if(!u32attr(a,&v)||v>INT_MAX)return -1;l->master=v;break;
   case IFLA_CARRIER:if(RTA_PAYLOAD(a)!=1)return -1;l->carrier=*(unsigned char*)RTA_DATA(a)!=0;l->has_carrier=true;break;
   case IFLA_LINKINFO:{int n=RTA_PAYLOAD(a);struct rtattr *x=RTA_DATA(a);for(;RTA_OK(x,n);x=RTA_NEXT(x,n))if((x->rta_type&NLA_TYPE_MASK)==IFLA_INFO_KIND){char kind[32];if(!stringattr(x,kind,sizeof(kind)))return -1;l->bridge=!strcmp(kind,"bridge");}if(n)return -1;break;}
  }
 }return len||l->index<=0||!*l->name?-1:0;
}
static int parse_addr(struct snapshot *s,const struct nlmsghdr *h){
 struct rtattr *a;int len;if(attributes(h,sizeof(struct ifaddrmsg),&a,&len))return -1;
 const struct ifaddrmsg *m=NLMSG_DATA(h);if(m->ifa_family!=AF_INET)return -1;
 if(s->addrs_n==MAX_ADDRS||m->ifa_index>INT_MAX)return -1;struct address *p=&s->addrs[s->addrs_n++];
 p->index=m->ifa_index;p->prefix=m->ifa_prefixlen;p->scope=m->ifa_scope;p->flags=m->ifa_flags;
 for(;RTA_OK(a,len);a=RTA_NEXT(a,len))switch(a->rta_type&NLA_TYPE_MASK){
  case IFA_LOCAL:if(p->has_local||!u32attr(a,&p->local))return -1;p->has_local=true;break;
  case IFA_ADDRESS:if(p->has_address||!u32attr(a,&p->address))return -1;p->has_address=true;break;
  case IFA_LABEL:if(p->has_label||!stringattr(a,p->label,sizeof(p->label)))return -1;p->has_label=true;break;
  case IFA_FLAGS:if(!u32attr(a,&p->flags))return -1;break;
  case IFA_BROADCAST:p->broadcast=true;break;
  case IFA_CACHEINFO:if(RTA_PAYLOAD(a)!=sizeof(struct ifa_cacheinfo))return -1;break;
  default:p->unknown=true;break;
 }return len?-1:0;
}
static int parse_route(struct snapshot *s,const struct nlmsghdr *h){
 struct rtattr *a;int len;if(attributes(h,sizeof(struct rtmsg),&a,&len))return -1;
 const struct rtmsg *m=NLMSG_DATA(h);if(m->rtm_family!=AF_INET)return -1;
 if(s->routes_n==MAX_ROUTES)return -1;struct route *r=&s->routes[s->routes_n++];
 r->table=m->rtm_table;r->prefix=m->rtm_dst_len;r->src_prefix=m->rtm_src_len;r->tos=m->rtm_tos;
 r->type=m->rtm_type;r->scope=m->rtm_scope;r->protocol=m->rtm_protocol;r->flags=m->rtm_flags;
 for(;RTA_OK(a,len);a=RTA_NEXT(a,len)){uint32_t v;switch(a->rta_type&NLA_TYPE_MASK){
  case RTA_DST:if(r->has_dst||!u32attr(a,&r->dst))return -1;r->has_dst=true;break;
  case RTA_SRC:if(!u32attr(a,&r->src))return -1;break;
  case RTA_OIF:if(!u32attr(a,&r->oif))return -1;break;
  case RTA_TABLE:if(!u32attr(a,&v)||(r->table&&r->table!=v))return -1;r->table=v;break;
  case RTA_PREFSRC:if(r->has_pref||!u32attr(a,&r->pref))return -1;r->has_pref=true;break;
  case RTA_PRIORITY:if(r->has_metric||!u32attr(a,&r->metric))return -1;r->has_metric=true;break;
  case RTA_GATEWAY:r->gateway=true;break;case RTA_MULTIPATH:r->multipath=true;break;
  case RTA_CACHEINFO:if(RTA_PAYLOAD(a)!=sizeof(struct rta_cacheinfo))return -1;break;
  default:r->unknown=true;break;
 }}return len?-1:0;
}
static int parse_rule(struct snapshot *s,const struct nlmsghdr *h){
 struct rtattr *a;int len;if(attributes(h,sizeof(struct fib_rule_hdr),&a,&len))return -1;
 const struct fib_rule_hdr *m=NLMSG_DATA(h);uint32_t table=m->table,priority=0,v;
 if(m->family!=AF_INET||m->src_len||m->dst_len||m->tos||m->flags||m->action!=FR_ACT_TO_TBL)return -1;
 for(;RTA_OK(a,len);a=RTA_NEXT(a,len))switch(a->rta_type&NLA_TYPE_MASK){
  case FRA_TABLE:if(!u32attr(a,&v)||(table&&table!=v))return -1;table=v;break;
  case FRA_PRIORITY:if(!u32attr(a,&priority))return -1;break;
  case FRA_SUPPRESS_PREFIXLEN:if(!u32attr(a,&v)||v!=UINT32_MAX)return -1;break;
  case FRA_PROTOCOL:if(RTA_PAYLOAD(a)!=1)return -1;break;
  case FRA_PAD:if(RTA_PAYLOAD(a))return -1;break;
  default:return -1;
 }
 unsigned bit=table==RT_TABLE_LOCAL&&priority==0?1:table==RT_TABLE_MAIN&&priority==32766?2:table==RT_TABLE_DEFAULT&&priority==32767?4:0;
 if(len||!bit||(s->rules_mask&bit))return -1;s->rules_mask|=bit;return 0;
}
static int net_exchange(void *request,size_t size,unsigned expected,struct snapshot *s,bool *ambiguous,int64_t end){
 struct nlmsghdr *q=request;struct sockaddr_nl kernel={.nl_family=AF_NETLINK};
 if(++nl_sequence==0)++nl_sequence;q->nlmsg_seq=nl_sequence;q->nlmsg_pid=nl_port;
 if(ambiguous)*ambiguous=false;
 ssize_t sent=sendto(nl,request,size,MSG_DONTWAIT,(void*)&kernel,sizeof(kernel));
 if(sent!=(ssize_t)size){if(sent>=0){errno=EIO;if(ambiguous)*ambiguous=true;}return -1;}if(ambiguous)*ambiguous=true;
 unsigned messages=0;size_t bytes=0;
 for(;;){int64_t left=end-now_ms();if(left<=0){errno=ETIMEDOUT;return -1;}
  struct pollfd p={.fd=nl,.events=POLLIN};int n=poll(&p,1,left>INT_MAX?INT_MAX:(int)left);
  if(n<0&&errno==EINTR)continue;if(n<=0){if(!n)errno=ETIMEDOUT;return -1;}
  if(p.revents&(POLLERR|POLLHUP|POLLNVAL)){errno=EIO;return -1;}
  unsigned char buf[65536];struct sockaddr_nl from;struct iovec io={buf,sizeof(buf)};
  struct msghdr msg={.msg_name=&from,.msg_namelen=sizeof(from),.msg_iov=&io,.msg_iovlen=1};
  ssize_t got=recvmsg(nl,&msg,MSG_DONTWAIT);if(got<0&&errno==EINTR)continue;
  if(got<=0)return -1;
  if(msg.msg_flags&(MSG_TRUNC|MSG_CTRUNC)||msg.msg_namelen!=sizeof(from)||from.nl_family!=AF_NETLINK||from.nl_pid||from.nl_groups){errno=EPROTO;return -1;}
  if((bytes+=(size_t)got)>MAX_DUMP_BYTES){errno=EOVERFLOW;return -1;}
  int rem=got;for(struct nlmsghdr *h=(void*)buf;NLMSG_OK(h,rem);h=NLMSG_NEXT(h,rem)){
   if(++messages>MAX_MESSAGES||h->nlmsg_seq!=nl_sequence||(h->nlmsg_pid!=0&&h->nlmsg_pid!=nl_port)||
      (h->nlmsg_flags&NLM_F_DUMP_INTR)){errno=EPROTO;return -1;}
   if(h->nlmsg_type==NLMSG_ERROR){if(h->nlmsg_len<NLMSG_LENGTH(sizeof(struct nlmsgerr))){errno=EPROTO;return -1;}
    const struct nlmsgerr *e=NLMSG_DATA(h);if(e->msg.nlmsg_seq!=nl_sequence||e->msg.nlmsg_type!=q->nlmsg_type){errno=EPROTO;return -1;}
    if((!s||e->error)&&rem!=(int)NLMSG_ALIGN(h->nlmsg_len)){errno=EPROTO;return -1;}
    if(ambiguous)*ambiguous=false;if(e->error){errno=-e->error;return -1;}if(!s)return 0;continue;}
   if(h->nlmsg_type==NLMSG_DONE){if(!s){errno=EPROTO;return -1;}
    if(rem!=(int)NLMSG_ALIGN(h->nlmsg_len)){errno=EPROTO;return -1;}
    if(h->nlmsg_len>NLMSG_LENGTH(0)){int result;if(h->nlmsg_len<NLMSG_LENGTH(sizeof(result))){errno=EPROTO;return -1;}memcpy(&result,NLMSG_DATA(h),sizeof(result));if(result){errno=result<0?-result:result;return -1;}}
    return 0;}
   if(!s||h->nlmsg_type!=expected){errno=EPROTO;return -1;}
   int ok=expected==RTM_NEWLINK?parse_link(s,h):expected==RTM_NEWADDR?parse_addr(s,h):expected==RTM_NEWROUTE?parse_route(s,h):parse_rule(s,h);
   if(ok){errno=EPROTO;return -1;}
  }if(rem){errno=EPROTO;return -1;}
 }
}
static int snapshot(struct snapshot *s){memset(s,0,sizeof(*s));int64_t end=now_ms()+SNAPSHOT_MS;
 const unsigned types[]={RTM_GETLINK,RTM_GETADDR,RTM_GETROUTE,RTM_GETRULE};
 const unsigned answers[]={RTM_NEWLINK,RTM_NEWADDR,RTM_NEWROUTE,RTM_NEWRULE};
 const size_t lengths[]={sizeof(struct ifinfomsg),sizeof(struct ifaddrmsg),sizeof(struct rtmsg),sizeof(struct fib_rule_hdr)};
 for(unsigned i=0;i<4;++i){unsigned char request[NLMSG_SPACE(sizeof(struct ifinfomsg))]={0};struct nlmsghdr *h=(void*)request;
  h->nlmsg_len=NLMSG_LENGTH(lengths[i]);h->nlmsg_type=types[i];h->nlmsg_flags=NLM_F_REQUEST|NLM_F_DUMP;
  *(unsigned char*)NLMSG_DATA(h)=i?AF_INET:AF_UNSPEC;
  if(net_exchange(request,h->nlmsg_len,answers[i],s,NULL,end))return -1;
 }if(s->rules_mask!=7){errno=EPROTO;return -1;}return 0;
}
static const struct link *find_link(const struct snapshot *s,const char *name){const struct link *found=NULL;
 for(unsigned i=0;i<s->links_n;++i)if(!strcmp(s->links[i].name,name)){if(found){errno=EPROTO;return NULL;}found=&s->links[i];}return found;}
static bool enrolled(const struct link *l){return l&&l->type==ARPHRD_ETHER&&l->has_mac&&!memcmp(l->mac,mac,6);}
static bool normal_br_ipv4(const struct snapshot *s,int index){for(unsigned i=0;i<s->addrs_n;++i){const struct address *a=&s->addrs[i];uint32_t v=ntohl(a->local);
 if(a->index==index&&a->has_local&&!strcmp(a->label,BR)&&a->scope==RT_SCOPE_UNIVERSE&&a->prefix>0&&a->prefix<32&&
    v&&((v>>24)!=127)&&((v>>16)!=0xa9fe)&&(v>>24)<224)return true;}return false;}
/* 0 means boot prerequisite not yet ready; -1 means unknown/unsafe identity. */
static int desired(const struct snapshot *s,struct owned *want){const struct link *eth=find_link(s,ETH),*br=find_link(s,BR),*chosen;
 if(!eth)return 0;if(!enrolled(eth)){if(!eth_enrolled_seen)return 0;errno=EPERM;return -1;}eth_enrolled_seen=true;
 if(!(eth->flags&IFF_UP)||!eth->has_carrier||!eth->carrier)return 0;
 if(!eth->master)chosen=eth;
 else {if(!br||!br->bridge||eth->master!=br->index){errno=EPERM;return -1;}
  if(!enrolled(br)){if(!bridge_enrolled_seen)return 0;errno=EPERM;return -1;}bridge_enrolled_seen=true;
  if(!(br->flags&IFF_UP)||!br->has_carrier||!br->carrier||!normal_br_ipv4(s,br->index))return 0;
  /* Do not defeat ASUS loop prevention by changing STP/port state. */
  char port_state[16];if(proc_text("/sys/class/net/eth0/brport/state",port_state,sizeof(port_state)))return -1;
  if(strcmp(port_state,"3\n"))return 0;chosen=br;}
 memset(want,0,sizeof(*want));want->present=true;want->index=chosen->index;strcpy(want->name,chosen->name);return 1;
}
static int policy_integer(const char *device,const char *key,int *value){char path[160],text[32],extra;int v;
 int n=snprintf(path,sizeof(path),"/proc/sys/net/ipv4/conf/%s/%s",device,key);
 if(n<0||(size_t)n>=sizeof(path)||proc_text(path,text,sizeof(text))||sscanf(text,"%d\n%c",&v,&extra)!=1||v<0||v>8)return -1;
 char canonical[16];snprintf(canonical,sizeof(canonical),"%d\n",v);if(strcmp(text,canonical)){errno=EPROTO;return -1;}*value=v;return 0;
}
static int policy(const char *device){const char *keys[]={"rp_filter","arp_ignore","arp_filter","arp_announce"};
 for(unsigned i=0;i<4;++i){int a,b;if(policy_integer("all",keys[i],&a)||policy_integer(device,keys[i],&b))return -1;
  int max=a>b?a:b;if((i==0&&max>2)||(i==1&&max>1)||(i>=2&&max!=0)){errno=EPERM;return -1;}}
 return 0;
}
static bool same_addr(const struct address *a,const struct owned *o){return o->present&&a->index==o->index&&a->has_local&&a->has_address&&a->has_label&&
 a->local==self_ip&&a->address==self_ip&&!strcmp(a->label,label(o->name))&&a->prefix==32&&a->scope==RT_SCOPE_LINK&&
 a->flags==(IFA_F_PERMANENT|IFA_F_NOPREFIXROUTE)&&!a->broadcast&&!a->unknown;}
static bool same_route(const struct route *r,const struct owned *o){return o->present&&r->has_dst&&r->dst==peer_ip&&r->prefix==32&&r->src_prefix==0&&
 r->src==0&&r->tos==0&&r->table==RT_TABLE_MAIN&&r->oif==(uint32_t)o->index&&r->has_pref&&r->pref==self_ip&&r->has_metric&&r->metric==METRIC&&
 r->type==RTN_UNICAST&&r->scope==RT_SCOPE_LINK&&r->protocol==PROTO&&(r->flags==0||r->flags==RTNH_F_LINKDOWN)&&!r->gateway&&!r->multipath&&!r->unknown;}
/* Ownership survives the kernel carrier-down marker; READY never does. */
static bool live_route(const struct snapshot *s,const struct owned *o){unsigned matched=0;
 for(unsigned i=0;i<s->routes_n;++i)if(same_route(&s->routes[i],o)){
  if(s->routes[i].flags!=0)return false;matched++;}
 return matched==1;
}
static int objects(const struct snapshot *s,const struct owned *o,unsigned *ac,unsigned *rc){*ac=*rc=0;
 for(unsigned i=0;i<s->addrs_n;++i){const struct address *a=&s->addrs[i];
  if((a->has_local&&a->local==peer_ip)||(a->has_address&&a->address==peer_ip)){errno=EEXIST;return -1;}
  if(a->local==self_ip||a->address==self_ip||!strcmp(a->label,"eth0:lr")||!strcmp(a->label,"br0:lr")){
   if(!same_addr(a,o)||++*ac>1){errno=EEXIST;return -1;}}
 }
 for(unsigned i=0;i<s->routes_n;++i){const struct route *r=&s->routes[i];
  if(r->prefix==32&&r->has_dst&&r->dst==peer_ip){
   if(!same_route(r,o)){fprintf(stderr,"LEON_RESCUE routeflags=%u reason=owned-peer-identity-or-status\n",r->flags);errno=EEXIST;return -1;}
   if(++*rc>1){errno=EEXIST;return -1;}
   if(r->flags==RTNH_F_LINKDOWN)fprintf(stderr,"LEON_RESCUE owned-route-kernel-status=%u\n",r->flags);
  }
  if(r->prefix==32&&r->has_dst&&r->dst==self_ip){
   bool local=*ac==1&&r->type==RTN_LOCAL&&r->table==RT_TABLE_LOCAL&&r->oif==(uint32_t)o->index&&r->scope==RT_SCOPE_HOST&&
    r->protocol==RTPROT_KERNEL&&r->has_pref&&r->pref==self_ip&&!r->gateway&&!r->multipath&&!r->unknown&&r->src_prefix==0&&r->tos==0;
   if(!local){errno=EEXIST;return -1;}}
 }
 if(o->present&&(*ac||*rc)){const struct link *l=find_link(s,o->name);if(!enrolled(l)||l->index!=o->index){errno=EPERM;return -1;}}
 return 0;
}
static int addattr(struct nlmsghdr *h,size_t cap,unsigned type,const void *data,size_t n){size_t at=NLMSG_ALIGN(h->nlmsg_len),len=RTA_LENGTH(n);
 if(at+RTA_ALIGN(len)>cap){errno=EOVERFLOW;return -1;}struct rtattr *a=(void*)((char*)h+at);a->rta_type=type;a->rta_len=len;memcpy(RTA_DATA(a),data,n);h->nlmsg_len=at+RTA_ALIGN(len);return 0;}
static int change(const struct owned *o,bool route,bool add,bool *ambiguous){unsigned char buf[512]={0};struct nlmsghdr *h=(void*)buf;
 h->nlmsg_type=route?(add?RTM_NEWROUTE:RTM_DELROUTE):(add?RTM_NEWADDR:RTM_DELADDR);
 h->nlmsg_flags=NLM_F_REQUEST|NLM_F_ACK|(add?(NLM_F_CREATE|NLM_F_EXCL):0);
 if(route){struct rtmsg *m=NLMSG_DATA(h);h->nlmsg_len=NLMSG_LENGTH(sizeof(*m));
  m->rtm_family=AF_INET;m->rtm_dst_len=32;m->rtm_table=RT_TABLE_MAIN;m->rtm_protocol=PROTO;m->rtm_scope=RT_SCOPE_LINK;m->rtm_type=RTN_UNICAST;
  uint32_t index=o->index,metric=METRIC;
  if(addattr(h,sizeof(buf),RTA_DST,&peer_ip,4)||addattr(h,sizeof(buf),RTA_OIF,&index,4)||addattr(h,sizeof(buf),RTA_PREFSRC,&self_ip,4)||addattr(h,sizeof(buf),RTA_PRIORITY,&metric,4))return -1;
 }else{struct ifaddrmsg *m=NLMSG_DATA(h);h->nlmsg_len=NLMSG_LENGTH(sizeof(*m));m->ifa_family=AF_INET;m->ifa_prefixlen=32;m->ifa_scope=RT_SCOPE_LINK;m->ifa_index=o->index;m->ifa_flags=IFA_F_PERMANENT;
  uint32_t flags=IFA_F_PERMANENT|IFA_F_NOPREFIXROUTE;const char *tag=label(o->name);
  if(addattr(h,sizeof(buf),IFA_LOCAL,&self_ip,4)||addattr(h,sizeof(buf),IFA_ADDRESS,&self_ip,4)||addattr(h,sizeof(buf),IFA_LABEL,tag,strlen(tag)+1)||addattr(h,sizeof(buf),IFA_FLAGS,&flags,4))return -1;
 }
 return net_exchange(buf,h->nlmsg_len,0,NULL,ambiguous,now_ms()+OP_MS);
}
static int withdraw(struct owned *o,struct snapshot *s){unsigned a,r;if(!o->present)return 0;
 if(o->phase!=P_ADDR&&o->phase!=P_ACTIVE){errno=EINPROGRESS;return fail("intent-retained-no-automatic-retry");}
 if(snapshot(s)||objects(s,o,&a,&r))return -1;
 if(!a&&!r)return owned_clear(o);
 if(r){if(o->phase!=P_ACTIVE||owned_save(o,P_ROUTE_DELETE))return -1;bool ambiguous;
  if(change(o,true,false,&ambiguous))return fail("route-delete-outcome-retained");
  if(snapshot(s)||objects(s,o,&a,&r)||r){errno=EIO;return -1;}if(owned_save(o,P_ADDR))return -1;}
 if(a){if(owned_save(o,P_ADDR_DELETE))return -1;bool ambiguous;
  if(change(o,false,false,&ambiguous))return fail("address-delete-outcome-retained");
  if(snapshot(s)||objects(s,o,&a,&r)||a||r){errno=EIO;return -1;}}
 return owned_clear(o);
}
static int install_owned(struct owned *o,const struct owned *want,struct snapshot *s){unsigned a,r;struct owned clear={0},again;
 if(snapshot(s)||objects(s,&clear,&a,&r)||desired(s,&again)!=1||again.index!=want->index||strcmp(again.name,want->name)||policy(want->name))return -1;
 *o=*want;if(owned_save(o,P_ADDR_INTENT))return -1;bool ambiguous;
 if(change(o,false,true,&ambiguous)){
  /* Definite failure means the address is not ours. Do not delete/adopt it. */
  int e=errno;if(!ambiguous&&owned_clear(o))return -1;errno=e;return fail("address-add");}
 if(snapshot(s)||objects(s,o,&a,&r)||a!=1||r){errno=EIO;return -1;}
 if(owned_save(o,P_ADDR))return -1;
 if(desired(s,&again)!=1||again.index!=o->index||strcmp(again.name,o->name)||policy(o->name))return withdraw(o,s);
 if(owned_save(o,P_ROUTE_INTENT))return -1;
 if(change(o,true,true,&ambiguous)){
  int e=errno;if(!ambiguous&&owned_save(o,P_ADDR))return -1;errno=e;return fail("route-add");}
 if(snapshot(s)||objects(s,o,&a,&r)||a!=1||r!=1){errno=EIO;return -1;}
 if(owned_save(o,P_ACTIVE))return -1;
 if(!live_route(s,o))return withdraw(o,s);return 0;
}
static int notify_ready(void){const char *path=getenv("NOTIFY_SOCKET");if(!path||strlen(path)>=sizeof(((struct sockaddr_un*)0)->sun_path)||(path[0]!='/'&&path[0]!='@')){errno=EINVAL;return -1;}
 struct sockaddr_un sa={.sun_family=AF_UNIX};size_t n=strlen(path);memcpy(sa.sun_path,path,n+1);if(path[0]=='@')sa.sun_path[0]=0;
 int fd=socket(AF_UNIX,SOCK_DGRAM|SOCK_CLOEXEC|SOCK_NONBLOCK,0);if(fd<0)return -1;
 const char msg[]="READY=1\nSTATUS=Owned labelled uplink rescue address and peer route installed";
 ssize_t sent=sendto(fd,msg,sizeof(msg)-1,MSG_DONTWAIT|MSG_NOSIGNAL,(void*)&sa,offsetof(struct sockaddr_un,sun_path)+n+(path[0]=='@'?0:1));int e=errno;close(fd);
 if(sent!=(ssize_t)sizeof(msg)-1){errno=e;return -1;}return 0;
}
int main(int argc,char **argv){umask(0077);bool cleanup=argc==2&&!strcmp(argv[1],"--cleanup-owned");
 if(argc!=2||(!cleanup&&strcmp(argv[1],"--monitor"))){fprintf(stderr,"usage: rescue-link --monitor|--cleanup-owned\n");return 125;}
 if(initialize())return 125;struct owned own;if(owned_load(&own))return fail("ownership-receipt"),125;
 struct snapshot *s=calloc(1,sizeof(*s));if(!s)return 125;
 if(cleanup){int r=withdraw(&own,s);free(s);return r?125:0;}
 struct sigaction act={.sa_handler=stop_handler};sigemptyset(&act.sa_mask);sigaction(SIGTERM,&act,NULL);sigaction(SIGINT,&act,NULL);
 bool ready=false;int64_t started=now_ms();int rc=0;
 /* Stable same-boot leftovers are withdrawn before reconfiguration. Intent
  * receipts remain a refusal; an automatic restart must not guess outcomes. */
 if(own.present&&withdraw(&own,s)){free(s);return 125;}
 while(!stopping){unsigned a,r;struct owned want;
  if(native_ns()||snapshot(s)||objects(s,&own,&a,&r)){rc=125;fail("snapshot-or-foreign-state");break;}
  int d=desired(s,&want);if(d<0){rc=125;fail("unknown-link-master");break;}
  /* Leave room for bounded cleanup before the unit's startup timeout. */
  if(!ready&&now_ms()-started>250000){errno=ETIMEDOUT;rc=125;fail("initial-uplink-timeout");break;}
  bool same=d==1&&own.present&&own.phase==P_ACTIVE&&own.index==want.index&&!strcmp(own.name,want.name)&&a==1&&r==1&&live_route(s,&own);
  if(own.present&&(!same||policy(own.name))){if(withdraw(&own,s)){rc=125;break;}same=false;}
  /* Finish already-sent ACK/readback or cleanup, but do not start another
   * install after TERM, including during a master transition. */
  if(stopping)break;
  if(d==1&&!same){if(install_owned(&own,&want,s)){rc=125;break;}}
  if(stopping)break;
  if(own.present&&own.phase==P_ACTIVE){
   /* A topology change during the multi-message transaction must reconcile
    * before READY. Normal ASUS/DHCP updates are not treated as helper writes. */
   if(snapshot(s)||objects(s,&own,&a,&r)||desired(s,&want)!=1||want.index!=own.index||strcmp(want.name,own.name)||a!=1||r!=1||!live_route(s,&own)||policy(own.name)){
    if(withdraw(&own,s)){rc=125;break;}continue;}
   if(!ready){if(notify_ready()){rc=125;break;}ready=true;fprintf(stderr,"LEON_RESCUE ready address=" SELF_IP " peer=" PEER_IP "\n");}
  }
  struct timespec wait={.tv_sec=1};while(nanosleep(&wait,&wait)&&errno==EINTR&&!stopping){}
 }
 if(withdraw(&own,s)){rc=125;fail("cleanup-retained");}free(s);return rc;
}
