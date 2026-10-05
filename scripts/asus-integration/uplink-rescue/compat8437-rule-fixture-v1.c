/* New raw SDK4.19 rule-header cases only. Include complete production source;
 * never invoke its daemon, sockets, service, ownership or write functions. */
#define main rescue_daemon_entry
#include "rescue-link-v6.c"
#undef main

union fixture_message {struct nlmsghdr align;unsigned char bytes[256];};
static unsigned fixture_cases;
static struct snapshot fixture_snapshot;
static void fixture_require(bool value,const char *name){
 if(!value){fprintf(stderr,"LEON_COMPAT8437_RULE_CASE_FAILED %s\n",name);exit(1);}
}
static void fixture_pass(const char *name){
 printf("LEON_COMPAT8437_RULE_CASE_PASS %s\n",name);fixture_cases++;
}
static void fixture_attr(union fixture_message *message,unsigned type,const void *value,size_t bytes){
 struct nlmsghdr *h=(void*)message->bytes;size_t at=NLMSG_ALIGN(h->nlmsg_len),n=RTA_LENGTH(bytes);
 fixture_require(at+RTA_ALIGN(n)<=sizeof(message->bytes),"synthetic-buffer-bound");
 struct rtattr *a=(void*)(message->bytes+at);a->rta_type=type;a->rta_len=n;
 if(bytes)memcpy(RTA_DATA(a),value,bytes);h->nlmsg_len=at+RTA_ALIGN(n);
}
static void fixture_rule(union fixture_message *message,unsigned header,bool full_table,uint32_t table,uint32_t priority){
 memset(message,0,sizeof(*message));struct nlmsghdr *h=(void*)message->bytes;
 h->nlmsg_len=NLMSG_LENGTH(sizeof(struct fib_rule_hdr));h->nlmsg_type=RTM_NEWRULE;
 struct fib_rule_hdr *m=NLMSG_DATA(h);m->family=AF_INET;m->table=header;m->action=FR_ACT_TO_TBL;
 /* Match fib_nl_fill_rule: full table, suppress=-1, protocol, and priority
  * only when nonzero. Default rules use RTPROT_KERNEL; ip-added rules may0. */
 if(full_table)fixture_attr(message,FRA_TABLE,&table,sizeof(table));
 uint32_t suppress=UINT32_MAX;fixture_attr(message,FRA_SUPPRESS_PREFIXLEN,&suppress,sizeof(suppress));
 unsigned char protocol=table<256?RTPROT_KERNEL:RTPROT_UNSPEC;
 fixture_attr(message,FRA_PROTOCOL,&protocol,sizeof(protocol));
 if(priority)fixture_attr(message,FRA_PRIORITY,&priority,sizeof(priority));
}
static struct rtattr *fixture_find_attr(union fixture_message *message,unsigned type){
 struct nlmsghdr *h=(void*)message->bytes;struct rtattr *a;int len;
 fixture_require(attributes(h,sizeof(struct fib_rule_hdr),&a,&len)==0,"synthetic-attribute-base");
 for(;RTA_OK(a,len);a=RTA_NEXT(a,len))if(a->rta_type==type)return a;
 fixture_require(false,"synthetic-attribute-found");return NULL;
}
static void fixture_defaults(bool with_default){
 memset(&fixture_snapshot,0,sizeof(fixture_snapshot));union fixture_message message;
 fixture_rule(&message,RT_TABLE_LOCAL,true,RT_TABLE_LOCAL,0);
 fixture_require(parse_rule(&fixture_snapshot,(void*)message.bytes)==0&&fixture_snapshot.rules_mask==1,"actual-emitted-local-no-priority");
 fixture_rule(&message,RT_TABLE_MAIN,true,RT_TABLE_MAIN,32766);
 fixture_require(parse_rule(&fixture_snapshot,(void*)message.bytes)==0&&fixture_snapshot.rules_mask==3,"actual-emitted-main");
 if(with_default){fixture_rule(&message,RT_TABLE_DEFAULT,true,RT_TABLE_DEFAULT,32767);
  fixture_require(parse_rule(&fixture_snapshot,(void*)message.bytes)==0&&fixture_snapshot.rules_mask==7,"actual-emitted-default");}
}
static void fixture_refused(const char *name,union fixture_message *message){
 fixture_defaults(true);
 fixture_require(parse_rule(&fixture_snapshot,(void*)message->bytes)==-1&&fixture_snapshot.rules_mask==7,name);
 fixture_pass(name);
}
int main(void){
 union fixture_message message;uint32_t value;
 fixture_defaults(true);fixture_pass("actual-default-emitted-three-mask7-pass");
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);
 fixture_require(parse_rule(&fixture_snapshot,(void*)message.bytes)==0&&fixture_snapshot.rules_mask==15,"raw252-8437-fourth");
 fixture_pass("raw252-8437-priority20-mask15-pass");
 fixture_require(parse_rule(&fixture_snapshot,(void*)message.bytes)==-1&&fixture_snapshot.rules_mask==15,"raw252-8437-duplicate-rule");
 fixture_pass("raw252-8437-duplicate-rule-refused");
 fixture_rule(&message,RT_TABLE_COMPAT,false,8437,20);
 fixture_refused("raw252-missing-full-table-refused",&message);
 fixture_rule(&message,RT_TABLE_UNSPEC,true,8437,20);
 fixture_refused("raw0-full8437-noncanonical-refused",&message);
 fixture_rule(&message,RT_TABLE_MAIN,true,8437,20);
 fixture_refused("raw254-full8437-conflict-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8438,20);
 fixture_refused("raw252-full8438-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,RT_TABLE_COMPAT,20);
 fixture_refused("raw252-full252-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);value=8437;fixture_attr(&message,FRA_TABLE,&value,sizeof(value));
 fixture_refused("raw252-duplicate-full8437-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);value=8438;fixture_attr(&message,FRA_TABLE,&value,sizeof(value));
 fixture_refused("raw252-conflicting-duplicate-table-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);fixture_find_attr(&message,FRA_TABLE)->rta_len=RTA_LENGTH(3);
 fixture_refused("raw252-short-full-table-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);value=1;fixture_attr(&message,FRA_FWMARK,&value,sizeof(value));
 fixture_refused("raw252-unknown-rule-attribute-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,21);
 fixture_refused("raw252-8437-wrong-priority-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);value=20;fixture_attr(&message,FRA_PRIORITY,&value,sizeof(value));
 fixture_refused("raw252-duplicate-priority-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);value=0;memcpy(RTA_DATA(fixture_find_attr(&message,FRA_SUPPRESS_PREFIXLEN)),&value,sizeof(value));
 fixture_refused("raw252-nondefault-suppression-refused",&message);
 fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);fixture_find_attr(&message,FRA_PROTOCOL)->rta_len=RTA_LENGTH(2);
 fixture_refused("raw252-protocol-shape-refused",&message);
 fixture_defaults(false);fixture_rule(&message,RT_TABLE_COMPAT,true,8437,20);
 fixture_require(parse_rule(&fixture_snapshot,(void*)message.bytes)==0&&fixture_snapshot.rules_mask==11,"raw252-no-default-mask11");
 /* Observe the real parser mask; the runner source-binds the production
  * snapshot gate rather than implementing a replacement completion gate. */
 fixture_pass("raw252-missing-default-observed-mask11");
 printf("LEON_COMPAT8437_RULE_ALL_CASES_PASS count=%u\n",fixture_cases);return 0;
}
