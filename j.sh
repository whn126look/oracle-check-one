#!/bin/bash

## 实例个数 告警日志 实例状态 会话 活动会话 锁 集群状态 服务状态 磁盘空间 侦听日志
## 单机、RAC  Linux、AIX  11g、19c、23ai
## 依赖adrci配置正常，也可以改为 getAlert()
## ver 1.2

case `uname` in
    AIX)
        ps aux |head -1 ; ps aux|sort -rn +2|head -5
        echo

        ps aux|head -1;ps aux | sort +5 -6 -n -r | head -5
        echo

        df|grep -e "[8,9][0-9]%" -e "100%"

        inst_cnt=`ps -ef|grep ckpt|grep -vE 'grep|ASM|MGMT'|awk '{print $9}' | wc -l`
        if [ $inst_cnt -gt 1 ]; then
           ps -ef|grep ckpt|grep -vE 'grep|ASM|MGMT'|awk '{print $9}'|awk -F'_' '{print "INSTANCE: " $3}'|sort
        fi

        PROFILE='.profile'
    ;;
    Linux)
        ## CPU较高的进程
        ps aux --sort=-%cpu| head -5
        echo

        ##内存较高的进程
        ps aux|head -1;ps aux|grep -v PID|sort -rn -k +4|head -5
        echo

        ##磁盘空间使用率超过80
        df -h|grep -v Size|sed 's#[[:space:]][[:space:]]*# #g'|cut -d ' ' -f5,6|sort -t '%' -k1 -nr|egrep '[8-9][0-9]%|100%' 

        ##实例个数大于1，提醒 ora_ckpt_FEX2
        inst_cnt=`ps -ef| grep ckpt|egrep -v 'grep|ASM|MGMT' | wc -l`
        if [ $inst_cnt -gt 1 ]; then
           ps xao pid,user,cmd|grep ckpt|grep -vE 'grep|ASM|MGMT' |awk '{print $3}'|awk -F'_' '{print "INSTANCE: " $3}'|sort
        fi

        PROFILE='.bash_profile'
    ;;
    *)
 echo "Unsupported OS type!"
 exit;
esac

rm -fr /tmp/israc.tmp

CMDFILE=/tmp/oracle_check.sh
(cat  << EOF
#!/bin/bash
source /home/oracle/$PROFILE
sid=\$1
echo "----------------------------"
echo \$sid
echo "----------------------------"

ORACLE_SID=\$sid

##登录用户及口令放到一个临时文件，例如sys/Welcome1 as sysdba
if [ -f '/tmp/pwdfile.tmp' ]; then
    sqlpwd=\`cat /tmp/pwdfile.tmp\`
else
    sqlpwd=' /as sysdba '
fi

getAlert() {
sqlplus -S "\$sqlpwd" <<!
set lin 200 pages 1000
col message_text for a80
col riqi for a22
select to_char(originating_timestamp,'yyyy-mm-dd hh24:mi:ss')riqi,message_text
from x\\\$dbgalertext
where originating_timestamp > sysdate - 3 and
  (message_text = 'ORA-00600'
OR message_text LIKE '%fatal%'
OR message_text LIKE '%error%'
OR message_text LIKE '%ORA-%'
OR message_text LIKE '%terminating the instance%');
exit
!
}

ver=\` sqlplus -v|grep Release|awk '{print \$3}'|cut -b 1-2 \`

##显示告警日志
if [ \${ver} -gt "11" ]; then
	aa=\`adrci exec="show home"|grep \$sid \`
	adrci exec="set home \$aa;show alert -p \"message_text like '%ORA-%'\" -term " |tail -6
else
	# adrci  exec="set home $aa;show alert -tail 5000"|grep ORA |tail -10 ## 11g
    echo \${ver}
    getAlert
fi


##实例状态

getInstance() {
sqlplus -S "\$sqlpwd" <<!
set lines 150
col status for a12
col instance_name for a15
col instance_name for a15
col startup_time for a20
col db_role for a20
col os for a20
col host_name for a25
col VERSION for a15
select instance_name,status,to_char(startup_time,'yyyy-mm-dd hh24:mi:ss')startup_time,host_name,(select database_role from v\\\$database)db_role,(select PLATFORM_NAME from v\\\$database)os,VERSION from gv\\\$instance order by 1;
exit
!
}

getInstance

showPdbs() {
sqlplus -S "\$sqlpwd" <<!
sho pdbdet
exit
!
}

##多租户信息
if [ \${ver} -gt "12" ]; then
	showPdbs
fi

sqlplus -S "\$sqlpwd" <<!
--会话个数 
col status for a12
col username for a30
select inst_id,username,count(0) cnt from gv\\\$session group by inst_id,username order by 1,2;

--top 10
set lines 200 pages 100
col txt for a65
col sql_id for a13
select a.sql_id,a.cnt,a.pctload,b.sql_text txt from (select * from (select sql_id,count(0) cnt,round(count(0)/sum(count(0)) over(),4)*100 pctload
from gv\\\$active_session_history A
where A.SAMPLE_TIME>sysdate-15/60/24
and sql_id is not null GROUP BY SQL_ID ORDER BY COUNT(0) DESC)
where rownum<11) a left join (select distinct sql_text,sql_id from v\\\$sqltext where piece=0) b on a.sql_id=b.sql_id order by 2 desc ,1;

col state for a20
col event for a25 trunc
select inst_id inst,sid,sql_id,event,state,blocking_session blk,last_call_et,seconds_in_wait miao
 from gv\\\$session where status='ACTIVE' and username is not null and sid<>sys_context('userenv','sid') and wait_class<>'Idle'
order by last_call_et;

--表空间使用率（mini）

col tablespace_name for a20
select a.tablespace_name, round(a.bytes / 1024 / 1024) "Sum MB", round((a.bytes - b.bytes) / 1024 / 1024) "used MB", round(b.bytes / 1024 / 1024) "free MB", round(((a.bytes - b.bytes) / a.bytes) * 100, 2) "percent_used"  from (select tablespace_name, sum(bytes) bytes          from dba_data_files         group by tablespace_name) a,       (select tablespace_name, sum(bytes) bytes, max(bytes) largest          from dba_free_space         group by tablespace_name) b where a.tablespace_name = b.tablespace_name order by ((a.bytes - b.bytes) / a.bytes) desc;


--查被阻塞会话 
set lin 200 pages 1000
col USERNAME for a15
col PROGRAM for a40
col EVENT for a30
col WAITING_SESSION for a20

WITH tkf_block_info AS
 (SELECT a.inst_id || '_' || a.sid waiting_session,
         a.username,  a.program,  a.event, a.sql_id,  a.last_call_et,
         DECODE(a.blocking_instance || '_' || a.blocking_session,
                '_', NULL, a.blocking_instance || '_' || a.blocking_session) holding_session
    FROM gv\\\$session a,
         (SELECT inst_id, sid
            FROM gv\\\$session
           WHERE blocking_session IS NOT NULL
          UNION
          SELECT blocking_instance, blocking_session
            FROM gv\\\$session
           WHERE blocking_session IS NOT NULL) b
   WHERE a.inst_id = b.inst_id
     AND a.SID = b.sid)
SELECT LPAD(' ', 3 * (LEVEL - 1)) || waiting_session waiting_session,
       username, program, event,  sql_id, last_call_et
  FROM tkf_block_info
CONNECT BY PRIOR waiting_session = holding_session
 START WITH holding_session IS NULL;
 
exit
!

getrole() {
sqlplus -S "\$sqlpwd" <<!
set head off
set feedback off
set echo off
set time off
set timing off
select database_role from v\\\$database;
exit
!
}

adg_diff() {
sqlplus -S "\$sqlpwd" <<!
col OPEN_MODE for a20
col PROTECTION_MODE for a20
col DATABASE_ROLE for a18
col SWITCHOVER_STATUS for a20
col thread# for 99
col name for a10
col diff for 9999
set lin 200
  select A.THREAD#,C.NAME,C.OPEN_MODE,C.PROTECTION_MODE,C.DATABASE_ROLE,C.SWITCHOVER_STATUS,A.APPLOG,B.NOWLOG, A.APPLOG- B.NOWLOG DIFF from (SELECT THREAD#, MAX(SEQUENCE#) AS "APPLOG" FROM v\\\$ARCHIVED_LOG WHERE APPLIED='YES' and RESETLOGS_CHANGE#=(select RESETLOGS_CHANGE# from v\\\$database) GROUP BY THREAD#) A,(SELECT THREAD#, MAX(SEQUENCE#) AS "NOWLOG" FROM v\\\$LOG GROUP BY THREAD#) B,v\\\$database C where A.THREAD#=B.THREAD#;

exit
!
} 


std_delay() {
sqlplus -S "\$sqlpwd" <<!
set lin 150
col name for a23
col VALUE for a18
col UNIT for a30
col TIME_COMPUTED for a20
col DATUM_TIME for a20
col SOURCE_DBID for 99999999999
col SOURCE_DB_UNIQUE_NAME for a20
 select name,value, TIME_COMPUTED,DATUM_TIME from v\\\$dataguard_stats;
exit
!
} 

is_rac() {
sqlplus -S "\$sqlpwd" <<!
set pagesize 9999 lin 250 echo off heading off verify off feedback off trims on
spool /tmp/israc.tmp app
select value from v\\\$parameter where name='cluster_database';
spool off
exit
!
} 

is_rac


role=\$(getrole)

role=\`echo \${role} |sed 's/ //g' \`
if [ \${role} = "PRIMARY" ]; then
  adg_diff
elif [ \${role} = "PHYSICALSTANDBY" ]; then
  std_delay
else
  echo 'error role'
fi
EOF

)>$CMDFILE
dbuser=`ps -ef|grep ora_ckpt|grep -v grep |awk '{print $1}'`


for ora_sid in `ps -ef|grep ckpt|grep -vE 'grep|ASM|MGMT'|awk '{print $8}'|awk -F'_' '{print $3}'|sort ` 
do
  su - $dbuser "-c /bin/bash $CMDFILE $ora_sid"
  echo
done



CMDFILE=/tmp/grid_check.sh
(cat  << EOF
#!/bin/bash
source /home/grid/$PROFILE
#集群状态 服务状态 磁盘空间 侦听日志
#crsctl stat res -t -init -w "(STATE = OFFLINE) and (NAME != ora.crf) and (NAME != ora.diskmon) and (NAME != ora.cha)"|grep -v '\----'|grep -v Cluster
crsctl stat res -t -init -w "(STATE = OFFLINE) and (NAME != ora.crf) and (NAME != ora.diskmon) and (NAME != ora.chad)" 
echo
crsctl stat res -t -w "(STATE = OFFLINE) and (NAME != ora.proxy_advm) and (NAME != ora.chad)" |grep -v '\-------'|grep -v 'Cluster Resources'
echo '------------------------------------------------------------'
crsctl stat res -t -w "NAME co prim" |grep -v '\-------'|grep -v 'Cluster Resources'
echo
EOF
)>$CMDFILE
giuser=`ps -ef|grep asm_ckpt|grep -v grep |awk '{print $1}'`

#判断是集群再跑crsctl检查
if [ -f '/tmp/israc.tmp' ]; then
	line=`cat /tmp/israc.tmp |grep -v ^$|head -1`
	if [ ${line} = "TRUE" ]; then
		su - $giuser  "-c /bin/bash $CMDFILE"
	fi
	echo
fi

w
echo

