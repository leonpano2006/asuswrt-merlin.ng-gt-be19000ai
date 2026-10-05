#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include "codb_utils.h"
#include "cosql_utils.h"

/* The only hardware-facing call is replaced in this isolated fixture. */
char *nvram_get(const char *key) {
    return !strcmp(key, "ex_db_backup_path") ? "/tmp/test-backup" : "";
}
/* Reject any unexpected hardware mutation reached from vendor libraries. */
void nvram_commit(void) { abort(); }
void nvram_unset(void) { abort(); }
void nvram_set(void) { abort(); }
void nvram_get_salt(void) { abort(); }
void wlcsm_nvram_get(void) { abort(); }
static void seed(const char *path, int when, int insert, int nonnull) {
    sqlite3 *db=NULL;
    assert(sqlite3_open(path,&db)==SQLITE_OK);
    assert(sqlite3_exec(db,"CREATE TABLE DATA_INFO(data_id INTEGER PRIMARY KEY,data_time INTEGER,a TEXT,b TEXT,c INTEGER,d TEXT);",NULL,NULL,NULL)==SQLITE_OK);
    if(insert) {
        char sql[512];
        snprintf(sql,sizeof(sql),"INSERT INTO DATA_INFO VALUES(1,%d,%s,'',0,'Unicode 中文 and quote \"');",when,nonnull?"'normal'":"NULL");
        assert(sqlite3_exec(db,sql,NULL,NULL,NULL)==SQLITE_OK);
    }
    assert(sqlite3_close(db)==SQLITE_OK);
}
int main(int argc,char **argv) {
    assert(argc==3);
    int nonnull=atoi(argv[2]);
    setenv("TZ","UTC",1);tzset();
    mkdir("/tmp/.diag",0700);mkdir("/tmp/test-backup",0700);mkdir("/tmp/test-backup/.diag",0700);
    int now=(int)time(NULL),start=now-30;
    int backup=!strcmp(argv[1],"backup");
    seed("/tmp/.diag/nulltest.db",now,!backup,nonnull);
    if(backup){
        char path[256];
        snprintf(path,sizeof(path),"/tmp/test-backup/.diag/%d_nulltest_1.0.db",start/86400*86400);
        seed(path,now,1,nonnull);
    }
    json_object *result=NULL;
    int rc;
    if(!strcmp(argv[1],"raw"))
        rc=codb_content_query_json_field("nulltest",4,"a;b;c;d",0,"",start,now+1,"ASC",10,&result);
    else
        rc=codb_content_query_duration_json_field("nulltest",4,"a;b;c;d",0,"",start,start+60,60,&result);
    assert(rc==0 && result);
    printf("RESULT %s\n",json_object_to_json_string(result));
    json_object_put(result);
    return 0;
}
