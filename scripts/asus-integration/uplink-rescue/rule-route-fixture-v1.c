/* Pure parser/predicate fixture: the complete production source is included.
 * The renamed daemon entry and all service/netlink/write paths are never called. */
#define main rescue_daemon_entry
#include "rescue-link-v4.c"
#undef main

union fixture_rule_message {struct nlmsghdr align;unsigned char bytes[256];};
static unsigned fixture_case_count;
static void fixture_require(bool value,const char *name){
 if(!value){fprintf(stderr,"LEON_ASUS_RULE_ROUTE_CASE_FAILED %s\n",name);exit(1);}
}
static void fixture_pass(const char *name){
 printf("LEON_ASUS_RULE_ROUTE_CASE_PASS %s\n",name);fixture_case_count++;
}
static void fixture_attr(union fixture_rule_message *message,unsigned type,const void *value,size_t bytes){
 struct nlmsghdr *h=(void*)message->bytes;size_t at=NLMSG_ALIGN(h->nlmsg_len),n=RTA_LENGTH(bytes);
 fixture_require(at+RTA_ALIGN(n)<=sizeof(message->bytes),"synthetic-rule-buffer-bound");
 struct rtattr *a=(void*)(message->bytes+at);a->rta_type=type;a->rta_len=n;
 if(bytes)memcpy(RTA_DATA(a),value,bytes);h->nlmsg_len=at+RTA_ALIGN(n);
}
static struct fib_rule_hdr *fixture_rule(union fixture_rule_message *message,uint32_t table,uint32_t priority){
 memset(message,0,sizeof(*message));struct nlmsghdr *h=(void*)message->bytes;
 h->nlmsg_len=NLMSG_LENGTH(sizeof(struct fib_rule_hdr));h->nlmsg_type=RTM_NEWRULE;
 struct fib_rule_hdr *m=NLMSG_DATA(h);m->family=AF_INET;m->table=table<=UINT8_MAX?table:RT_TABLE_UNSPEC;m->action=FR_ACT_TO_TBL;
 fixture_attr(message,FRA_TABLE,&table,sizeof(table));fixture_attr(message,FRA_PRIORITY,&priority,sizeof(priority));
 return m;
}
static int fixture_parse(struct snapshot *s,union fixture_rule_message *message){
 return parse_rule(s,(void*)message->bytes);
}
static void fixture_standard_rules(struct snapshot *s,bool with_default){
 memset(s,0,sizeof(*s));union fixture_rule_message message;
 fixture_rule(&message,RT_TABLE_LOCAL,0);fixture_require(fixture_parse(s,&message)==0,"standard-local");
 fixture_rule(&message,RT_TABLE_MAIN,32766);fixture_require(fixture_parse(s,&message)==0,"standard-main");
 if(with_default){fixture_rule(&message,RT_TABLE_DEFAULT,32767);fixture_require(fixture_parse(s,&message)==0,"standard-default");}
}
static struct route fixture_route(const char *destination,unsigned prefix){
 struct route r={.table=8437,.prefix=prefix,.has_dst=true,.type=RTN_UNICAST,.scope=RT_SCOPE_LINK,.protocol=RTPROT_KERNEL};
 fixture_require(inet_pton(AF_INET,destination,&r.dst)==1,"synthetic-route-address");return r;
}
static void fixture_route_case(const char *name,const struct route *r,bool expected){
 fixture_require(asus_8437_route_disjoint(r)==expected,name);fixture_pass(name);
}
int main(void){
 static struct snapshot s;union fixture_rule_message message;struct fib_rule_hdr *m;struct route r;uint32_t value;
 fixture_require(inet_pton(AF_INET,SELF_IP,&self_ip)==1&&inet_pton(AF_INET,PEER_IP,&peer_ip)==1,"synthetic-rescue-endpoints");
 fixture_standard_rules(&s,true);fixture_require(s.rules_mask==7,"default-three-rules");fixture_pass("rules-default-three");
 fixture_rule(&message,8437,20);fixture_require(fixture_parse(&s,&message)==0&&s.rules_mask==15,"actual-fourth-rule");fixture_pass("rules-exact-fourth-20-8437");
 fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==15,"duplicate-fourth-rule");fixture_pass("rules-duplicate-fourth-refused");
 fixture_standard_rules(&s,true);fixture_rule(&message,8438,20);fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==7,"wrong-table");fixture_pass("rules-wrong-table-refused");
 fixture_rule(&message,8437,21);fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==7,"wrong-priority");fixture_pass("rules-wrong-priority-refused");
 m=fixture_rule(&message,8437,20);m->dst_len=24;fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==7,"destination-selector");fixture_pass("rules-destination-selector-refused");
 m=fixture_rule(&message,8437,20);m->src_len=24;fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==7,"source-selector");fixture_pass("rules-source-selector-refused");
 m=fixture_rule(&message,8437,20);m->flags=1;fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==7,"rule-flags");fixture_pass("rules-flags-refused");
 m=fixture_rule(&message,8437,20);m->action=FR_ACT_BLACKHOLE;fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==7,"wrong-action");fixture_pass("rules-wrong-action-refused");
 fixture_rule(&message,8437,20);value=1;fixture_attr(&message,FRA_FWMARK,&value,sizeof(value));fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==7,"unknown-rule-attribute");fixture_pass("rules-unknown-attribute-refused");
 fixture_rule(&message,8437,20);value=8437;fixture_attr(&message,FRA_TABLE,&value,sizeof(value));fixture_require(fixture_parse(&s,&message)==-1&&s.rules_mask==7,"duplicate-rule-attribute");fixture_pass("rules-duplicate-attribute-refused");
 fixture_standard_rules(&s,false);fixture_require(s.rules_mask==3,"missing-default-mask");
 fixture_rule(&message,8437,20);fixture_require(fixture_parse(&s,&message)==0&&s.rules_mask==11,"missing-default-with-optional-mask");
 /* The production snapshot completion gate is source-bound by the runner.
  * This observation does not duplicate that gate in a fixture implementation. */
 fixture_pass("rules-missing-default-observed-mask11");
 r=fixture_route("10.23.0.0",24);fixture_route_case("route-disjoint-subnet-pass",&r,true);
 r=fixture_route("10.23.0.9",32);fixture_route_case("route-disjoint-host-pass",&r,true);
 r=fixture_route(SELF_IP,32);fixture_route_case("route-self-host-refused",&r,false);
 r=fixture_route(PEER_IP,32);fixture_route_case("route-peer-host-refused",&r,false);
 r=fixture_route("169.254.190.0",24);fixture_route_case("route-covering-subnet-refused",&r,false);
 r=fixture_route("0.0.0.0",0);fixture_route_case("route-default-refused",&r,false);
 r.type=RTN_BLACKHOLE;fixture_route_case("route-covering-blackhole-refused",&r,false);
 r=fixture_route("169.254.190.0",24);r.type=RTN_THROW;fixture_route_case("route-covering-throw-refused",&r,false);
 r=fixture_route("10.23.0.1",24);fixture_route_case("route-noncanonical-refused",&r,false);
 r=fixture_route("10.23.0.0",24);r.has_dst=false;fixture_route_case("route-missing-dst-refused",&r,false);
 r=fixture_route("10.23.0.0",33);fixture_route_case("route-prefix33-refused",&r,false);
 r=fixture_route("10.23.0.0",24);r.unknown=true;fixture_route_case("route-unknown-refused",&r,false);
 r=fixture_route("10.23.0.0",24);r.gateway=true;fixture_route_case("route-gateway-refused",&r,false);
 r=fixture_route("10.23.0.0",24);r.multipath=true;fixture_route_case("route-multipath-refused",&r,false);
 r=fixture_route("10.23.0.0",24);r.src_prefix=24;fixture_route_case("route-source-prefix-refused",&r,false);
 r=fixture_route("10.23.0.0",24);r.src=1;fixture_route_case("route-source-value-refused",&r,false);
 r=fixture_route("10.23.0.0",24);r.tos=1;fixture_route_case("route-tos-refused",&r,false);
 printf("LEON_ASUS_RULE_ROUTE_ALL_CASES_PASS count=%u\n",fixture_case_count);return 0;
}
