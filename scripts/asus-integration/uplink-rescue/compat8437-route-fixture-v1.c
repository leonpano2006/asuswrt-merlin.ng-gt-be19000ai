/* New raw SDK4.19 route-header cases only. Include complete production source;
 * never invoke its daemon, sockets, service, ownership or write functions. */
#define main rescue_daemon_entry
#include "rescue-link-v5.c"
#undef main

union fixture_message {struct nlmsghdr align;unsigned char bytes[256];};
static unsigned fixture_cases;
static struct snapshot fixture_snapshot;
static void fixture_require(bool value,const char *name){
 if(!value){fprintf(stderr,"LEON_COMPAT8437_CASE_FAILED %s\n",name);exit(1);}
}
static void fixture_attr(union fixture_message *message,unsigned type,const void *value,size_t bytes){
 struct nlmsghdr *h=(void*)message->bytes;size_t at=NLMSG_ALIGN(h->nlmsg_len),n=RTA_LENGTH(bytes);
 fixture_require(at+RTA_ALIGN(n)<=sizeof(message->bytes),"synthetic-buffer-bound");
 struct rtattr *a=(void*)(message->bytes+at);a->rta_type=type;a->rta_len=n;
 if(bytes)memcpy(RTA_DATA(a),value,bytes);h->nlmsg_len=at+RTA_ALIGN(n);
}
static void fixture_route(union fixture_message *message,unsigned header,bool full_table,const char *destination,unsigned prefix){
 memset(message,0,sizeof(*message));struct nlmsghdr *h=(void*)message->bytes;
 h->nlmsg_len=NLMSG_LENGTH(sizeof(struct rtmsg));h->nlmsg_type=RTM_NEWROUTE;
 struct rtmsg *m=NLMSG_DATA(h);m->rtm_family=AF_INET;m->rtm_table=header;
 m->rtm_dst_len=prefix;m->rtm_type=RTN_UNICAST;m->rtm_scope=RT_SCOPE_LINK;m->rtm_protocol=RTPROT_KERNEL;
 uint32_t value=8437;if(full_table)fixture_attr(message,RTA_TABLE,&value,sizeof(value));
 if(destination){fixture_require(inet_pton(AF_INET,destination,&value)==1,"synthetic-destination");fixture_attr(message,RTA_DST,&value,sizeof(value));}
 value=33;fixture_attr(message,RTA_OIF,&value,sizeof(value));
}
static void fixture_case(const char *name,union fixture_message *message,bool expected_parse,bool expected_disjoint){
 memset(&fixture_snapshot,0,sizeof(fixture_snapshot));int result=parse_route(&fixture_snapshot,(void*)message->bytes);
 fixture_require((result==0)==expected_parse,name);
 if(expected_parse){
  fixture_require(fixture_snapshot.routes_n==1&&fixture_snapshot.routes[0].table==8437,name);
  fixture_require(asus_8437_route_disjoint(&fixture_snapshot.routes[0])==expected_disjoint,name);
 }
 printf("LEON_COMPAT8437_CASE_PASS %s\n",name);fixture_cases++;
}
int main(void){
 union fixture_message message;uint32_t value;struct rtnexthop hop={.rtnh_len=sizeof(hop),.rtnh_ifindex=33};
 fixture_require(inet_pton(AF_INET,SELF_IP,&self_ip)==1&&inet_pton(AF_INET,PEER_IP,&peer_ip)==1,"synthetic-endpoints");
 fixture_route(&message,RT_TABLE_COMPAT,true,"10.23.0.0",24);
 fixture_case("raw252-8437-disjoint-subnet-pass",&message,true,true);
 fixture_route(&message,RT_TABLE_COMPAT,true,"10.23.0.9",32);
 fixture_case("raw252-8437-disjoint-host-pass",&message,true,true);
 fixture_route(&message,RT_TABLE_COMPAT,true,SELF_IP,32);
 fixture_case("raw252-8437-self-overlap-refused",&message,true,false);
 fixture_route(&message,RT_TABLE_COMPAT,true,PEER_IP,32);
 fixture_case("raw252-8437-peer-overlap-refused",&message,true,false);
 fixture_route(&message,RT_TABLE_COMPAT,true,"169.254.190.0",24);
 fixture_case("raw252-8437-covering-prefix-refused",&message,true,false);
 fixture_route(&message,RT_TABLE_COMPAT,true,NULL,0);
 fixture_case("raw252-8437-default-refused",&message,true,false);
 fixture_route(&message,RT_TABLE_COMPAT,false,"10.23.0.0",24);
 fixture_case("raw252-missing-full-table-refused",&message,false,false);
 fixture_route(&message,RT_TABLE_COMPAT,false,"10.23.0.0",24);value=8438;fixture_attr(&message,RTA_TABLE,&value,sizeof(value));
 fixture_case("raw252-unknown-full-table-refused",&message,false,false);
 fixture_route(&message,RT_TABLE_COMPAT,false,"10.23.0.0",24);value=RT_TABLE_COMPAT;fixture_attr(&message,RTA_TABLE,&value,sizeof(value));
 fixture_case("raw252-full-table252-refused",&message,false,false);
 fixture_route(&message,RT_TABLE_MAIN,true,"10.23.0.0",24);
 fixture_case("raw254-full-table8437-conflict-refused",&message,false,false);
 fixture_route(&message,RT_TABLE_UNSPEC,true,"10.23.0.0",24);
 fixture_case("raw0-full-table8437-noncanonical-refused",&message,false,false);
 fixture_route(&message,RT_TABLE_COMPAT,true,"10.23.0.0",24);value=8437;fixture_attr(&message,RTA_TABLE,&value,sizeof(value));
 fixture_case("raw252-duplicate-full-table-refused",&message,false,false);
 fixture_route(&message,RT_TABLE_COMPAT,true,"10.23.0.0",24);value=8438;fixture_attr(&message,RTA_TABLE,&value,sizeof(value));
 fixture_case("raw252-conflicting-duplicate-table-refused",&message,false,false);
 fixture_route(&message,RT_TABLE_COMPAT,false,"10.23.0.0",24);value=8437;fixture_attr(&message,RTA_TABLE,&value,3);
 fixture_case("raw252-short-full-table-refused",&message,false,false);
 fixture_route(&message,RT_TABLE_COMPAT,true,"10.23.0.0",24);value=1;fixture_attr(&message,RTA_MAX+1,&value,sizeof(value));
 fixture_case("raw252-8437-unknown-attribute-refused",&message,true,false);
 fixture_route(&message,RT_TABLE_COMPAT,true,"10.23.0.0",24);fixture_require(inet_pton(AF_INET,"10.23.0.254",&value)==1,"synthetic-gateway");fixture_attr(&message,RTA_GATEWAY,&value,sizeof(value));
 fixture_case("raw252-8437-gateway-refused",&message,true,false);
 fixture_route(&message,RT_TABLE_COMPAT,true,"10.23.0.0",24);fixture_attr(&message,RTA_MULTIPATH,&hop,sizeof(hop));
 fixture_case("raw252-8437-multipath-refused",&message,true,false);
 printf("LEON_COMPAT8437_ALL_CASES_PASS count=%u\n",fixture_cases);return 0;
}
