#include "gwlib/gwlib.h"

#define SQL_SELECT_SMPP_USERS "SELECT id,systemId,password,systemType \
FROM smppUser where systemId='%s' and password='%s' and systemType='%s' "

#define SQL_INSERT_MT "INSERT INTO trafficMT (id,phoneNumber,shortNumber,receivedTime,deliveryTime,dispatchTime,deliveryCount,msgText,carrierMsgId,integratorMsgId,status,errCode,errText,serviceId,serviceName,carrierId,integratorId,integratorQueueId,connectionId) \
VALUES(NULL,'%S','%S',now(),now(),'0000-00-00 00:00:00',%s,'%S',%s,'%S','%s',%d,'%S',%S,'%S',%S,%S,%S,'%S')"

#define SQL_SELECT_MO "SELECT id,phoneNumber,shortNumber,receivedTime,deliveryTime,dispatchTime,deliveryCount,msgText,status,errCode,errText,serviceId,serviceName,carrierId,integratorId,integratorQueueId \
FROM trafficMO \
WHERE status='QUEUED' \
AND deliveryTime<=now() \
AND integratorQueueId=%s \
LIMIT 1000 "

#define SQL_SELECT_SERVICE "SELECT id,serviceName,connectionId FROM service \
WHERE shortNumber='%s' \
AND carrierId=%s \
AND integratorId=%s \
AND integratorQueueId=%s "

#define SQL_UPDATE_MO_STATUS "UPDATE trafficMO  \
SET status = '%s', \
	dispatchTime = now() \
WHERE id= %s "

#define SQL_SELECT_CARRIER_ROUTE "SELECT c.id AS id,c.name AS name,cast(group_concat(p.preffix separator ';') as char(5000) charset utf8) AS preffix \
FROM carrier c, preffixMapping p \
WHERE c.id = p.carrierId \
GROUP BY c.name"

#define SQL_SELECT_PORTED_NUMBER "SELECT carrierId FROM ported \
where portedNumber='%s' "

#define SQL_SELECT_BLACK_LIST "SELECT * FROM blackList \
where phoneNumber='%s' "

#define SQLBOX_MYSQL_CREATE_LOG_TABLE "CREATE TABLE IF NOT EXISTS %S ( \
sql_id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY, \
momt ENUM('MO', 'MT', 'DLR') NULL, sender VARCHAR(20) NULL, \
receiver VARCHAR(20) NULL, udhdata BLOB NULL, msgdata TEXT NULL, \
time BIGINT(20) NULL, smsc_id VARCHAR(255) NULL, service VARCHAR(255) NULL, \
account VARCHAR(255) NULL, id BIGINT(20) NULL, sms_type BIGINT(20) NULL, \
mclass BIGINT(20) NULL, mwi BIGINT(20) NULL, coding BIGINT(20) NULL, \
compress BIGINT(20) NULL, validity BIGINT(20) NULL, deferred BIGINT(20) NULL, \
dlr_mask BIGINT(20) NULL, dlr_url VARCHAR(255) NULL, pid BIGINT(20) NULL, \
alt_dcs BIGINT(20) NULL, rpi BIGINT(20) NULL, charset VARCHAR(255) NULL, \
boxc_id VARCHAR(255) NULL, binfo VARCHAR(255) NULL, meta_data TEXT)"

#define SQLBOX_MYSQL_CREATE_INSERT_TABLE "CREATE TABLE IF NOT EXISTS %S ( \
sql_id BIGINT(20) NOT NULL AUTO_INCREMENT PRIMARY KEY, \
momt ENUM('MO', 'MT') NULL, sender VARCHAR(20) NULL, \
receiver VARCHAR(20) NULL, udhdata BLOB NULL, msgdata TEXT NULL, \
time BIGINT(20) NULL, smsc_id VARCHAR(255) NULL, service VARCHAR(255) NULL, \
account VARCHAR(255) NULL, id BIGINT(20) NULL, sms_type BIGINT(20) NULL, \
mclass BIGINT(20) NULL, mwi BIGINT(20) NULL, coding BIGINT(20) NULL, \
compress BIGINT(20) NULL, validity BIGINT(20) NULL, deferred BIGINT(20) NULL, \
dlr_mask BIGINT(20) NULL, dlr_url VARCHAR(255) NULL, pid BIGINT(20) NULL, \
alt_dcs BIGINT(20) NULL, rpi BIGINT(20) NULL, charset VARCHAR(255) NULL, \
boxc_id VARCHAR(255) NULL, binfo VARCHAR(255) NULL, meta_data TEXT)"

#define SQLBOX_MYSQL_SELECT_QUERY "SELECT sql_id, momt, sender, receiver, udhdata, \
msgdata, time, smsc_id, service, account, id, sms_type, mclass, mwi, coding, \
compress, validity, deferred, dlr_mask, dlr_url, pid, alt_dcs, rpi, \
charset, boxc_id, binfo, meta_data FROM %S LIMIT 0,1"

#define SQLBOX_MYSQL_INSERT_QUERY "INSERT INTO %S ( sql_id, momt, sender, \
receiver, udhdata, msgdata, time, smsc_id, service, account, sms_type, \
mclass, mwi, coding, compress, validity, deferred, dlr_mask, dlr_url, \
pid, alt_dcs, rpi, charset, boxc_id, binfo, meta_data ) VALUES ( \
NULL, %S, %S, %S, %S, %S, %S, %S, %S, %S, %S, %S, %S, %S, %S, %S, %S, \
%S, %S, %S, %S, %S, %S, %S, %S, %S)"

#define SQLBOX_MYSQL_DELETE_QUERY "DELETE FROM %S WHERE sql_id = %S"

#include "gw/msg.h"
#include <mysql/mysql.h>

MYSQL_RES* mysql_select(const Octstr *sql);
void mysql_update(const Octstr *sql);
void sql_save_msg(Msg *msg, Octstr *momt);
Msg *mysql_fetch_msg();
void sql_shutdown();
struct server_type *sqlbox_init_mysql(Cfg* cfg);
Octstr *sqlbox_id;

struct server_type {
	Octstr *type;
	void (*sql_enter)(Cfg *);
	void (*sql_leave)();
	Msg *(*sql_fetch_msg)();
	void (*sql_save_msg)(Msg *, Octstr *);
};

