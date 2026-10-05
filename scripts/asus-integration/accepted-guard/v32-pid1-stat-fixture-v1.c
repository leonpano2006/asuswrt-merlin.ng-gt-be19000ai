/* SPDX-License-Identifier: GPL-2.0-or-later
 * Only the real v32 fixed PID1 stat parser runs, on bounded synthetic text.
 * The production collector, proc reads, volume checks and guardian never run.
 * Linker section GC removes those paths; old 25/14 cases are not replayed.
 */
#include "v32-runtime/accepted-core.c"
#include <assert.h>
#include <stdio.h>

static unsigned passed;
static void pass(const char *name){printf("PASS %s\n",name);++passed;}
static size_t sample(char *out,size_t capacity,const char *comm,const char *state,const char *parent,const char *started){
 int n=snprintf(out,capacity,"1 (%s) %s %s",comm,state,parent);assert(n>0&&(size_t)n<capacity);size_t used=(size_t)n;
 for(unsigned field=5;field<=21;++field){n=snprintf(out+used,capacity-used," 0");assert(n>0&&(size_t)n<capacity-used);used+=(size_t)n;}
 n=snprintf(out+used,capacity-used," %s 0\n",started);assert(n>0&&(size_t)n<capacity-used);return used+(size_t)n;
}
static void accepts(const char *name,const char *comm,const char *state,const char *started,uint64_t expected){
 char data[ACCEPT_PID1_STAT_CAPACITY];uint64_t value=99;size_t n=sample(data,sizeof(data),comm,state,"0",started);
 assert(!accepted_parse_pid1_stat(data,n,&value)&&value==expected);pass(name);
}
static void rejects(const char *name,const char *state,const char *parent,const char *started){
 char data[ACCEPT_PID1_STAT_CAPACITY];uint64_t value=99;size_t n=sample(data,sizeof(data),"systemd",state,parent,started);
 assert(accepted_parse_pid1_stat(data,n,&value)==-1&&value==99);pass(name);
}
int main(void){
 alarm(10);assert(!setvbuf(stdout,NULL,_IOLBF,0));
 accepts("literal-pid1-zero-start-pass","systemd","S","0",0);
 accepts("literal-pid1-positive-start-pass","systemd","R","17",17);
 accepts("start-uint64-max-pass","systemd","S","18446744073709551615",UINT64_MAX);
 accepts("last-close-parenthesis-comm-pass","system) d","S","0",0);
 accepts("embedded-newline-comm-pass","sys\ntemd","S","0",0);
 rejects("nonzero-parent-refused","S","1","0");
 rejects("negative-parent-refused","S","-1","0");
 rejects("negative-start-refused","S","0","-1");
 rejects("plus-start-refused","S","0","+0");
 rejects("start-uint64-overflow-refused","S","0","18446744073709551616");
 rejects("nondecimal-start-refused","S","0","0x0");
 rejects("zombie-pid1-refused","Z","0","0");
 rejects("unknown-state-refused","?","0","0");
 {
  char data[ACCEPT_PID1_STAT_CAPACITY];uint64_t value=99;size_t n=sample(data,sizeof(data),"systemd","S","0","0");data[0]='2';
  assert(accepted_parse_pid1_stat(data,n,&value)==-1&&value==99);pass("other-pid-zero-start-refused");
 }
 {
  char data[ACCEPT_PID1_STAT_CAPACITY];uint64_t value=99;size_t n=sample(data,sizeof(data),"systemd","S","0","0");data[9]=0;
  assert(accepted_parse_pid1_stat(data,n,&value)==-1&&value==99);pass("embedded-nul-refused");
 }
 {
  char data[ACCEPT_PID1_STAT_CAPACITY];uint64_t value=99;size_t n=sample(data,sizeof(data),"systemd","S","0","0");char *end=strrchr(data,')');assert(end);*end=' ';
  assert(accepted_parse_pid1_stat(data,n,&value)==-1&&value==99);pass("missing-comm-close-refused");
 }
 {
  char data[ACCEPT_PID1_STAT_CAPACITY];uint64_t value=99;size_t n=sample(data,sizeof(data),"systemd","S","0","0");assert(n>=4);
  assert(accepted_parse_pid1_stat(data,n-4,&value)==-1&&value==99);pass("missing-field22-refused");
 }
 {
  char data[ACCEPT_PID1_STAT_CAPACITY];uint64_t value=99;size_t n=sample(data,sizeof(data),"systemd","S","0","0");assert(n>=3);
  assert(accepted_parse_pid1_stat(data,n-3,&value)==-1&&value==99);pass("missing-field22-delimiter-refused");
 }
 {
  char data[ACCEPT_PID1_STAT_CAPACITY];uint64_t value=99;size_t n=sample(data,sizeof(data),"systemd","S","0","0");assert(n<sizeof(data));memset(data+n,' ',sizeof(data)-n);data[n-1]=' ';
  assert(accepted_parse_pid1_stat(data,sizeof(data),&value)==-1&&value==99);pass("capacity4096-refused-before-parse");
 }
 {
  uint64_t value=99;assert(accepted_parse_pid1_stat("",0,&value)==-1&&value==99);pass("empty-input-refused");
 }
 {
  const char data[]="1 ) S 0 0\n";uint64_t value=99;assert(accepted_parse_pid1_stat(data,sizeof(data)-1,&value)==-1&&value==99);pass("missing-comm-open-refused");
 }
 printf("V32_PID1_STAT_PARSER_PASS cases=%u\n",passed);return 0;
}
