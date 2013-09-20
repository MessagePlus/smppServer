/*
 * smppServer.c - SMPP V 3.4  Server
 */

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <math.h>

#include "gwlib/gwlib.h"
#include "gw/msg.h"
#include "gw/shared.h"
#include "gw/bb.h"

#include "gw/smsc/smpp_pdu.h"
#include "gw/sms.h"
#include "gw/heartbeat.h"
#include "gw/meta_data.h"
#include "mysqlDB.h"
#include "gw/dlr.h"

#undef GW_NAME
#undef GW_VERSION
#include "../sb-config.h"


/* our config */
static Cfg *cfg;
/* have we received restart cmd from bearerbox? */
static volatile sig_atomic_t restart_smppbox = 0;
static volatile sig_atomic_t smppbox_status;
#define SMPP_DEAD 0
#define SMPP_SHUTDOWN 1
#define SMPP_RUNNING 2
static long smppbox_port;
static Dict *list_dict;

static long sms_max_length = MAX_SMS_OCTETS;
static long smpp_source_addr_ton = -1;
static long smpp_source_addr_npi = -1;
static int smpp_autodetect_addr = 0;
static long smpp_dest_addr_ton = -1;
static long smpp_dest_addr_npi = -1;

static Octstr *smppbox_id;
static Octstr *integratorId;
static Octstr *integratorQueueId;
static Octstr *our_system_id;
static time_t smpp_timeout;
int transmitter_mode;
int receiver_mode;

#define TIMEOUT_SECONDS 300

typedef enum {
	SMPP_LOGIN_NOTLOGGEDIN, SMPP_LOGIN_TRANSMITTER, SMPP_LOGIN_RECEIVER, SMPP_LOGIN_TRANSCEIVER
} smpp_login;

enum {
	USE_UUID = 0, USE_SMPP_ID = 1
};

typedef struct _boxc {
	Connection *smpp_connection;
	smpp_login login_type;
	int logged_in;
	long id;
	int load;
	int version;
	Octstr *alt_charset;
	time_t connect_time;
	Counter *smpp_pdu_counter;
	Octstr *client_ip;
	List *outgoing;
	Dict *sent;
	Semaphore *pending;
	volatile sig_atomic_t alive;
	Octstr *boxc_id; /* identifies connected client */
	//Octstr *our_id; /* Idenfies us to our bearerbox */
	Octstr *sms_service; //
	Dict *msg_acks;
	Dict *deliver_acks;
	time_t last_pdu_received;
	/* used to mark connection usable or still waiting for ident. msg */
	volatile int routable;

	Octstr *service_type;
	long source_addr_ton;
	long source_addr_npi;
	int autodetect_addr;
	long dest_addr_ton;
	long dest_addr_npi;
	int alt_dcs;
	int validityperiod;
	int priority;
	int mo_recode;

} Boxc;

typedef struct _CarrierRoute {
	Octstr *id;
	Octstr *name;
	Octstr *preffix;
	int errorCode;
	Octstr *errorText;
} CarrierRoute;

typedef struct _service{
	Octstr *id;
	Octstr *name;
	Octstr *connectionId;
} Service;

CarrierRoute *carrierRoutes;
int numberCarrierRoutes;


static void msg_list_destroy(List *l) {
	long i, len;
	Msg *item;

	i = 0;
	len = gwlist_len(l);
	while (i < len) {
		item = gwlist_get(l, i);
		msg_destroy(item);
		item = NULL;
		++i;
	}
}

static void msg_list_destroy_item(void *item) {
	msg_list_destroy(item);
}

void smpp_pdu_destroy_item(void *pdu) {
	smpp_pdu_destroy(pdu);
}

static void shutdown_connection(Connection *conn) {
	conn_destroy(conn);
}

/* check if login exists in database */
int check_login(Boxc *boxc, Octstr *system_id, Octstr *password, Octstr *system_type, smpp_login login_type) {
	int success;
	success = search_smpp_user(system_id, password, system_type);
	if (success) {
		info(0, "Login success!! connection  from  host <%s>", octstr_get_cstr(boxc->client_ip));
		goto valid_login;
	}

	return 0;
	valid_login: return 1;
}

/*
 * Select these based on whether you want to dump SMPP PDUs as they are
 * sent and received or not. Not dumping should be the default in at least
 * stable releases.
 */

#define DEBUG 1

#ifndef DEBUG
#define dump_pdu(msg, id, pdu) do{}while(0)
#else
/** This version does dump. */
#define dump_pdu(msg, id, pdu)                  \
    do {                                        \
        debug("smppServer", 0, "SMPP[%s]: %s", \
            octstr_get_cstr(id), msg);          \
        smpp_pdu_dump(pdu);                     \
    } while(0)
#endif

static void dump_pdu_debug(char *msg, Octstr *id, SMPP_PDU *pdu) {
	debug("smppServer", 0, "SMPP[%s]: %s", octstr_get_cstr(id), msg);
	smpp_pdu_dump(pdu);
}

/*
 * Converting SMPP timestamp to minutes relative
 * to our localtime.
 * Return -1 if error detected
 * Author: amalysh@kannel.org
 */
static int timestamp_to_minutes(Octstr *timestamp) {
	struct tm tm, local;
	time_t valutc, utc;
	int rc, diff, dummy, localdiff;
	char relation;

	if (octstr_len(timestamp) == 0)
		return 0;

	if (octstr_len(timestamp) != 16)
		return -1;

	/*
	 * Timestamp format:
	 * YYMMDDhhmmsstnn[+-R]
	 * t - tenths of second (not used by us)
	 * nn - Time difference in quarter hours between local and UTC time
	 */
	rc = sscanf(octstr_get_cstr(timestamp), "%02d%02d%02d%02d%02d%02d%1d%02d%1c", &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
			&tm.tm_hour, &tm.tm_min, &tm.tm_sec, &dummy, &diff, &relation);
	if (rc != 9)
		return -1;

	utc = time(NULL);
	if (utc == ((time_t) -1))
		return 0;

	if (relation == '+' || relation == '-') {
		tm.tm_year += 100; /* number of years since 1900 */
		tm.tm_mon--; /* month 0-11 */
		tm.tm_isdst = -1;
		/* convert to sec. since 1970 */
		valutc = gw_mktime(&tm);
		if (valutc == ((time_t) -1))
			return -1;

		/* work out local time, because gw_mktime assume local time */
		local = gw_localtime(utc);
		tm = gw_gmtime(utc);
		local.tm_isdst = tm.tm_isdst = -1;
		localdiff = difftime(gw_mktime(&local), gw_mktime(&tm));
		valutc += localdiff;

		debug("smppServer", 0, "diff between utc and localtime (%d)", localdiff);
		diff = diff * 15 * 60;
		switch (relation) {
		case '+':
			valutc -= diff;
			break;
		case '-':
			valutc += diff;
			break;
		}
	} else if (relation == 'R') { /* relative to SMSC localtime */
		local = gw_localtime(utc);
		local.tm_year += tm.tm_year;
		local.tm_mon += tm.tm_mon;
		local.tm_mday += tm.tm_mday;
		local.tm_hour += tm.tm_hour;
		local.tm_min += tm.tm_min;
		local.tm_sec += tm.tm_sec;
		valutc = gw_mktime(&local);
		if (valutc == ((time_t) -1))
			return -1;
	} else {
		return -1;
	}
	tm = gw_gmtime(valutc);
	debug("smppServer", 0, "Requested UTC timestamp: %02d-%02d-%02d %02d:%02d:%02d", tm.tm_year + 1900, tm.tm_mon + 1,
			tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

	debug("smppServer", 0, "requested timestamp in min. (%ld)", (valutc - utc) / 60);

	return ceil(difftime(valutc, utc) / 60);
}

/*
 *-------------------------------------------------
 *  receiver thingies
 *-------------------------------------------------
 *
 */

/* send to bearerbox */

static int send_msg(Connection *conn, Msg *pmsg) {
	/* Caution: implicit msg_destroy */
	write_to_bearerbox_real(conn, pmsg);
	return 0;
}

Msg *catenate_msg(List *list, int total) {
	int current = 1, partno = 1, thismsg, max = 0;
	Msg *current_msg;
	Msg *ret = msg_duplicate(gwlist_get(list, 0));

	octstr_destroy(ret->sms.udhdata);
	ret->sms.udhdata = NULL;
	octstr_delete(ret->sms.msgdata, 0, octstr_len(ret->sms.msgdata));
	while (max < total) {
		current_msg = gwlist_get(list, current - 1);
		if (current_msg) {
			thismsg = octstr_get_char(current_msg->sms.udhdata, 5);
			if (thismsg == partno) {
				octstr_append(ret->sms.msgdata, current_msg->sms.msgdata);
				max = 0;
				if (++partno > total) {
					return ret;
				}
			}
		}
		if (current >= total) {
			current = 0;
		}
		current++;
		max++;
	}
	/* fail */
	debug("smppServer", 0, "re-assembling message failed.");
	msg_destroy(ret);
	return NULL;
}

static long convert_addr_from_pdu(Octstr *id, Octstr *addr, long ton, long npi) {
	long reason = SMPP_ESME_ROK;

	if (addr == NULL)
		return reason;

	switch (ton) {
	case GSM_ADDR_TON_INTERNATIONAL:
		/*
		 * Checks to perform:
		 *   1) assume international number has at least 7 chars
		 *   2) the whole source addr consist of digits, exception '+' in front
		 */
		if (octstr_len(addr) < 7) {
			warn(0, "SMPP[%s]: Mallformed addr `%s', expected at least 7 digits. ", octstr_get_cstr(id),
					octstr_get_cstr(addr));
			//reason = SMPP_ESME_RINVSRCADR;
			//goto error;
		} else if (octstr_get_char(addr, 0) == '+' && !octstr_check_range(addr, 1, 256, gw_isdigit)) {
			error(0, "SMPP[%s]: Mallformed addr `%s', expected all digits. ", octstr_get_cstr(id),
					octstr_get_cstr(addr));
			reason = SMPP_ESME_RINVSRCADR;
			goto error;
		} else if (octstr_get_char(addr, 0) != '+' && !octstr_check_range(addr, 0, 256, gw_isdigit)) {
			error(0, "SMPP[%s]: Mallformed addr `%s', expected all digits. ", octstr_get_cstr(id),
					octstr_get_cstr(addr));
			reason = SMPP_ESME_RINVSRCADR;
			goto error;
		}
		/* check if we received leading '00', then remove it*/
		if (octstr_search(addr, octstr_imm("00"), 0) == 0)
			octstr_delete(addr, 0, 2);

		/* international, insert '+' if not already here */
		//No se quiere agregar el simbolo +
		//if (octstr_get_char(addr, 0) != '+')
		//	octstr_insert_char(addr, 0, '+');
		break;
	case GSM_ADDR_TON_ALPHANUMERIC:
		if (octstr_len(addr) > 11) {
			/* alphanum sender, max. allowed length is 11 (according to GSM specs) */
			error(0, "SMPP[%s]: Mallformed addr `%s', alphanum length greater 11 chars. ", octstr_get_cstr(id),
					octstr_get_cstr(addr));
			reason = SMPP_ESME_RINVSRCADR;
			goto error;
		}
		break;
	default: /* otherwise don't touch addr, user should handle it */
		break;
	}

	error: return reason;
}

static int send_pdu(Connection *conn, Octstr *id, SMPP_PDU *pdu) {
	Octstr *os;
	int ret;

	dump_pdu("Sending PDU:", id, pdu);
	os = smpp_pdu_pack(id, pdu);
	if (os) {
		ret = conn_write(conn, os); /* Caller checks for write errors later */
		octstr_destroy(os);
	} else {
		ret = -1;
	}
	return ret;
}

/* generate 8 character ID, taken from msgid */
static Octstr *generate_smppid(Msg *msg) {
	char uuidbuf[UUID_STR_LEN + 1];
	Octstr *result;

	// gw_assert(msg->type == sms); // we segfault on this

	uuid_unparse(msg->sms.id, uuidbuf);
	result = octstr_create_from_data(uuidbuf, 8);
	return result;
}

/*
 * Try to read an SMPP PDU from a Connection. Return -1 for error (caller
 * should close the connection), 0 for no PDU to ready yet, or 1 for PDU
 * read and unpacked. Return a pointer to the PDU in `*pdu'. Use `*len'
 * to store the length of the PDU to read (it may be possible to read the
 * length, but not the rest of the PDU - we need to remember the lenght
 * for the next call). `*len' should be zero at the first call.
 */
static int read_pdu(Boxc *box, Connection *conn, long *len, SMPP_PDU **pdu) {
	Octstr *os;

	if (*len == 0) {
		*len = smpp_pdu_read_len(conn);
		if (*len == -1) {
			error(0, "smppServer[%s]: Server sent garbage, ignored.", octstr_get_cstr(box->boxc_id));
			return -1;
		} else if (*len == 0) {
			if (conn_eof(conn) || conn_error(conn))
				return -1;
			return 0;
		}
	}

	os = smpp_pdu_read_data(conn, *len);
	if (os == NULL) {
		if (conn_eof(conn) || conn_error(conn))
			return -1;
		return 0;
	}
	*len = 0;

	*pdu = smpp_pdu_unpack(box->boxc_id, os);
	if (*pdu == NULL) {
		error(0, "smppServer[%s]: PDU unpacking failed.", octstr_get_cstr(box->boxc_id));
		debug("smppServer", 0, "smppServer[%s]: Failed PDU omitted.", octstr_get_cstr(box->boxc_id));
		/* octstr_dump(os, 0); */
		octstr_destroy(os);
		return -1;
	}

	octstr_destroy(os);
	return 1;
}

static int msg_is_report_mo(Msg *msg) {
	return msg->sms.sms_type == report_mo;
}

static void change_box_id(Msg *msg) {
	octstr_destroy(msg->sms.boxc_id);
	msg->sms.boxc_id = octstr_duplicate(smppbox_id);
}

static List *msg_to_pdu(Boxc *box, Msg *msg) {
	SMPP_PDU *pdu, *pdu2;
	List *pdulist = gwlist_create(), *parts;
	int dlrtype, catenate;
	int dlr_state = 7; /* UNKNOWN */
	Msg *dlr;
	char *text, *tmps, err[4] = { '0', '0', '0', '\0' };
	char submit_date_c_str[11] = { '\0' }, done_date_c_str[11] = { '\0' };
	struct tm tm_tmp;
	Octstr *msgid, *msgid2, *dlr_status, *dlvrd;
	/* split variables */
	unsigned long msg_sequence, msg_count;
	unsigned long submit_date;
	int max_msgs;
	Octstr *header, *footer, *suffix, *split_chars;
	Msg *msg2;

	pdu = smpp_pdu_create(deliver_sm, counter_increase(box->smpp_pdu_counter));

	pdu->u.deliver_sm.source_addr = octstr_duplicate(msg->sms.sender);
	pdu->u.deliver_sm.destination_addr = octstr_duplicate(msg->sms.receiver);

	/* Set the service type of the outgoing message. We'll use the config
	 * directive as default and 'binfo' as specific parameter. */
	pdu->u.deliver_sm.service_type =
			octstr_len(msg->sms.binfo) ? octstr_duplicate(msg->sms.binfo) : octstr_duplicate(box->service_type);

	/* Check for manual override of source ton and npi values */
	if (box->source_addr_ton > -1 && box->source_addr_npi > -1) {
		pdu->u.deliver_sm.source_addr_ton = box->source_addr_ton;
		pdu->u.deliver_sm.source_addr_npi = box->source_addr_npi;
		debug("smppServer", 0, "SMPP[%s]: Manually forced source addr ton = %ld, source add npi = %ld",
				octstr_get_cstr(box->boxc_id), box->source_addr_ton, box->source_addr_npi);
	} else {
		/* setup default values */
		pdu->u.deliver_sm.source_addr_ton = GSM_ADDR_TON_NATIONAL; /* national */
		pdu->u.deliver_sm.source_addr_npi = GSM_ADDR_NPI_E164; /* ISDN number plan */
	}

	if (box->autodetect_addr) {
		/* lets see if its international or alphanumeric sender */
		if (octstr_get_char(pdu->u.deliver_sm.source_addr, 0) == '+') {
			if (!octstr_check_range(pdu->u.deliver_sm.source_addr, 1, 256, gw_isdigit)) {
				pdu->u.deliver_sm.source_addr_ton = GSM_ADDR_TON_ALPHANUMERIC; /* alphanum */
				pdu->u.deliver_sm.source_addr_npi = GSM_ADDR_NPI_UNKNOWN; /* short code */
			} else {
				/* numeric sender address with + in front -> international (remove the +) */
				octstr_delete(pdu->u.deliver_sm.source_addr, 0, 1);
				pdu->u.deliver_sm.source_addr_ton = GSM_ADDR_TON_INTERNATIONAL;
			}
		} else {
			if (!octstr_check_range(pdu->u.deliver_sm.source_addr, 0, 256, gw_isdigit)) {
				pdu->u.deliver_sm.source_addr_ton = GSM_ADDR_TON_ALPHANUMERIC;
				pdu->u.deliver_sm.source_addr_npi = GSM_ADDR_NPI_UNKNOWN;
			}
		}
	}

	/* Check for manual override of destination ton and npi values */
	if (box->dest_addr_ton > -1 && box->dest_addr_npi > -1) {
		pdu->u.deliver_sm.dest_addr_ton = box->dest_addr_ton;
		pdu->u.deliver_sm.dest_addr_npi = box->dest_addr_npi;
		debug("smppServer", 0, "SMPP[%s]: Manually forced dest addr ton = %ld, dest add npi = %ld",
				octstr_get_cstr(box->boxc_id), box->dest_addr_ton, box->dest_addr_npi);
	} else {
		pdu->u.deliver_sm.dest_addr_ton = GSM_ADDR_TON_NATIONAL; /* national */
		pdu->u.deliver_sm.dest_addr_npi = GSM_ADDR_NPI_E164; /* ISDN number plan */
	}

	/*
	 * if its a international number starting with +, lets remove the
	 * '+' and set number type to international instead
	 */
	if (octstr_get_char(pdu->u.deliver_sm.destination_addr, 0) == '+') {
		octstr_delete(pdu->u.deliver_sm.destination_addr, 0, 1);
		pdu->u.deliver_sm.dest_addr_ton = GSM_ADDR_TON_INTERNATIONAL;
	}

	/* check length of src/dst address */
	if (octstr_len(pdu->u.deliver_sm.destination_addr) > 20 || octstr_len(pdu->u.deliver_sm.source_addr) > 20) {
		smpp_pdu_destroy(pdu);

		gwlist_destroy(pdulist, smpp_pdu_destroy_item);
		warning(0, "smppServer: msg_to_pdu: address too long, not acceptable");
		return NULL;
	}

	/*
	 * set the data coding scheme (DCS) field
	 * check if we have a forced value for this from the smsc-group.
	 * Note: if message class is set, then we _must_ force alt_dcs otherwise
	 * dcs has reserved values (e.g. mclass=2, dcs=0x11). We check MWI flag
	 * first here, because MWI and MCLASS can not be set at the same time and
	 * function fields_to_dcs check MWI first, so we have no need to force alt_dcs
	 * if MWI is set.
	 */
	if (msg->sms.mwi == MWI_UNDEF && msg->sms.mclass != MC_UNDEF)
		pdu->u.deliver_sm.data_coding = fields_to_dcs(msg, 1); /* force alt_dcs */
	else
		pdu->u.deliver_sm.data_coding = fields_to_dcs(msg,
				(msg->sms.alt_dcs != SMS_PARAM_UNDEFINED ? msg->sms.alt_dcs : box->alt_dcs));

	/* set protocol id */
	if (msg->sms.pid != SMS_PARAM_UNDEFINED)
		pdu->u.deliver_sm.protocol_id = msg->sms.pid;

	/*
	 * set the esm_class field
	 * default is store and forward, plus udh and rpi if requested
	 */
	pdu->u.deliver_sm.esm_class = 0;
	if (octstr_len(msg->sms.udhdata))
		pdu->u.deliver_sm.esm_class = pdu->u.deliver_sm.esm_class | ESM_CLASS_SUBMIT_UDH_INDICATOR;
	if (msg->sms.rpi > 0)
		pdu->u.deliver_sm.esm_class = pdu->u.deliver_sm.esm_class | ESM_CLASS_SUBMIT_RPI;

	/* Is this a delivery report? */
	if (msg_is_report_mo(msg)) {
		pdu->u.deliver_sm.esm_class |= ESM_CLASS_DELIVER_SMSC_DELIVER_ACK;
		dlrtype = msg->sms.dlr_mask;
		parts = octstr_split(msg->sms.dlr_url, octstr_imm(";"));
		msgid = gwlist_extract_first(parts);

		dlr = dlr_find(box->boxc_id, msgid, msg->sms.receiver, dlrtype, 0);
		if (dlr == NULL) {
			/* we could not find a corresponding dlr; nothing to send */
			smpp_pdu_destroy(pdu);
			gwlist_destroy(pdulist, smpp_pdu_destroy_item);
			octstr_destroy(msgid);
			gwlist_destroy(parts, octstr_destroy_item);
			warning(0, "smppServer: msg_to_pdu: no msg corresponding dlr, ignoring");
			return NULL;
		}
		dlvrd = octstr_imm("000");
		switch (dlrtype) {
		case DLR_UNDEFINED:
		case DLR_NOTHING:
			dlr_state = 8;
			dlr_status = octstr_imm("REJECTD");
			break;
		case DLR_SUCCESS:
			dlr_state = 2;
			dlr_status = octstr_imm("DELIVRD");
			dlvrd = octstr_imm("001");
			break;
		case DLR_BUFFERED:
			dlr_state = 6;
			dlr_status = octstr_imm("ACCEPTD");
			break;
		case DLR_SMSC_SUCCESS:
			/* please note that this state does not quite conform to the SMMP v3.4 spec */
			dlr_state = 0;
			dlr_status = octstr_imm("BUFFRED");
			break;
		case DLR_FAIL:
		case DLR_SMSC_FAIL:
			dlr_state = 5;
			dlr_status = octstr_imm("UNDELIV");
			break;
		}

		text = octstr_get_cstr(msg->sms.msgdata);

		tmps = strstr(text, "err:");
		if (tmps != NULL) {
			/* we can't use 0-padding with %s, if this is really required,
			 * then convert the numeric string to a real integer. - st */
			snprintf(err, sizeof(err), "%3.3s", tmps + (4 * sizeof(char)));
			tmps = strstr(tmps, " ");
			text = tmps ? tmps + (1 * sizeof(char)) : "";
		}

		tmps = strstr(text, "text:");
		if (tmps != NULL) {
			text = tmps + (5 * sizeof(char));
		}

		/* restore original submission date from service */
		submit_date = 0;
		if (octstr_len(dlr->sms.service) > 0) {
			sscanf(octstr_get_cstr(dlr->sms.service), "%ld", &submit_date);
		}
		if (!submit_date || submit_date > dlr->sms.time) {
			submit_date = msg->sms.time;
		}

		tm_tmp = gw_localtime(submit_date);
		gw_strftime(submit_date_c_str, sizeof(submit_date_c_str), "%y%m%d%H%M", &tm_tmp);

		tm_tmp = gw_localtime(dlr->sms.time);
		gw_strftime(done_date_c_str, sizeof(done_date_c_str), "%y%m%d%H%M", &tm_tmp);

		/* the msgids are in dlr->dlr_url as reported by Victor Luchitz */
		gwlist_destroy(parts, octstr_destroy_item);
		parts = octstr_split(dlr->sms.dlr_url, octstr_imm(";"));
		octstr_destroy(gwlist_extract_first(parts));
		if (gwlist_len(parts) > 0) {
			while ((msgid2 = gwlist_extract_first(parts)) != NULL) {
				debug("smppServer", 0, "DLR for multipart message: sending %s.", octstr_get_cstr(msgid2));
				pdu2 = smpp_pdu_create(deliver_sm, counter_increase(box->smpp_pdu_counter));
				pdu2->u.deliver_sm.esm_class = pdu->u.deliver_sm.esm_class;
				pdu2->u.deliver_sm.source_addr_ton = pdu->u.deliver_sm.source_addr_ton;
				pdu2->u.deliver_sm.source_addr_npi = pdu->u.deliver_sm.source_addr_npi;
				pdu2->u.deliver_sm.dest_addr_ton = pdu->u.deliver_sm.dest_addr_ton;
				pdu2->u.deliver_sm.dest_addr_npi = pdu->u.deliver_sm.dest_addr_npi;
				pdu2->u.deliver_sm.data_coding = pdu->u.deliver_sm.data_coding;
				pdu2->u.deliver_sm.protocol_id = pdu->u.deliver_sm.protocol_id;
				pdu2->u.deliver_sm.source_addr = octstr_duplicate(
						pdu->u.deliver_sm.source_addr);
				pdu2->u.deliver_sm.destination_addr = octstr_duplicate(
						pdu->u.deliver_sm.destination_addr);
				pdu2->u.deliver_sm.service_type = octstr_duplicate(
						pdu->u.deliver_sm.service_type);
				if (box->version > 0x33) {
					pdu2->u.deliver_sm.receipted_message_id = octstr_duplicate(
							msgid2);
					pdu2->u.deliver_sm.message_state = dlr_state;
					dict_destroy(pdu->u.deliver_sm.tlv);
					pdu2->u.deliver_sm.tlv = meta_data_get_values(msg->sms.meta_data, "smpp");
				}
				pdu2->u.deliver_sm.short_message = octstr_format(
						"id:%S sub:001 dlvrd:%S submit date:%s done date:%s stat:%S err:%s text:%12s", msgid2, dlvrd,
						submit_date_c_str, done_date_c_str, dlr_status, err, text);
				octstr_destroy(msgid2);
				gwlist_append(pdulist, pdu2);
			}
			smpp_pdu_destroy(pdu);
		} else {
			if (box->version > 0x33) {
				pdu->u.deliver_sm.receipted_message_id = octstr_duplicate(
						msgid);
				pdu->u.deliver_sm.message_state = dlr_state;
				dict_destroy(pdu->u.deliver_sm.tlv);
				pdu->u.deliver_sm.tlv = meta_data_get_values(msg->sms.meta_data, "smpp");
			}
			pdu->u.deliver_sm.short_message = octstr_format(
					"id:%S sub:001 dlvrd:%S submit date:%s done date:%s stat:%S err:%s text:%12s", msgid, dlvrd,
					submit_date_c_str, done_date_c_str, dlr_status, err, text);
			gwlist_append(pdulist, pdu);
		}
		octstr_destroy(msgid);
		msg_destroy(dlr);
		gwlist_destroy(parts, octstr_destroy_item);
		return pdulist;
	} else {
		/* ask for the delivery reports if needed */
		if (DLR_IS_SUCCESS_OR_FAIL(msg->sms.dlr_mask))
			pdu->u.deliver_sm.registered_delivery = 1;
		else if (DLR_IS_FAIL(msg->sms.dlr_mask) && !DLR_IS_SUCCESS(msg->sms.dlr_mask))
			pdu->u.deliver_sm.registered_delivery = 2;
		/*
		 * set data segments and length
		 */

		pdu->u.deliver_sm.short_message = octstr_duplicate(msg->sms.msgdata);

	}

	/*
	 * only re-encoding if using default smsc charset that is defined via
	 * alt-charset in smsc group and if MT is not binary
	 */
	if (msg->sms.coding == DC_7BIT || (msg->sms.coding == DC_UNDEF && octstr_len(msg->sms.udhdata))) {
		/*
		 * consider 3 cases:
		 *  a) data_coding 0xFX: encoding should always be GSM 03.38 charset
		 *  b) data_coding 0x00: encoding may be converted according to alt-charset
		 *  c) data_coding 0x00: assume GSM 03.38 charset if alt-charset is not defined
		 */
		if ((pdu->u.deliver_sm.data_coding & 0xF0) || (!box->alt_charset && pdu->u.deliver_sm.data_coding == 0)) {
			charset_utf8_to_gsm(pdu->u.deliver_sm.short_message);
		} else if (pdu->u.deliver_sm.data_coding == 0 && box->alt_charset) {
			/*
			 * convert to the given alternative charset
			 */
			if (charset_convert(pdu->u.deliver_sm.short_message, "ISO-8859-1", octstr_get_cstr(box->alt_charset)) != 0)
				error(0, "Failed to convert msgdata from charset <%s> to <%s>, will send as is.", "ISO-8859-1",
						octstr_get_cstr(box->alt_charset));
		}
	}

	/* prepend udh if present */
	if (octstr_len(msg->sms.udhdata)) {
		octstr_insert(pdu->u.deliver_sm.short_message, msg->sms.udhdata, 0);
	}

	pdu->u.deliver_sm.sm_length = octstr_len(pdu->u.deliver_sm.short_message);

	/* set priority */
	if (msg->sms.priority >= 0 && msg->sms.priority <= 3)
		pdu->u.deliver_sm.priority_flag = msg->sms.priority;
	else
		pdu->u.deliver_sm.priority_flag = box->priority;

	/* set more messages to send */
	/*
	 if (box->version > 0x33 && msg->sms.msg_left > 0)
	 pdu->u.deliver_sm.more_messages_to_send = 1;
	 */

	header = NULL;
	footer = NULL;
	suffix = NULL;
	split_chars = NULL;
	catenate = 1;
	max_msgs = 255;
//	if (catenate)
//		msg_sequence = counter_increase(catenated_sms_counter) & 0xFF;
//	else
//		msg_sequence = 0;

	/* split sms */
	parts = sms_split(msg, header, footer, suffix, split_chars, catenate, msg_sequence, max_msgs, sms_max_length);
	msg_count = gwlist_len(parts);

	if ((msg_count > 1) && (box->version > 0x33)) {
		Octstr *use_message_payload_meta;
		long use_message_payload;

		use_message_payload_meta = meta_data_get_value(msg->sms.meta_data, "smpp", octstr_imm("use_message_payload"));
		use_message_payload = strtol(octstr_get_cstr(use_message_payload_meta), 0, 0);

		if (use_message_payload) {
			/* copy short message data to message_payload TLV */
			pdu->u.deliver_sm.message_payload = octstr_duplicate(
					pdu->u.deliver_sm.short_message);
			octstr_destroy(pdu->u.deliver_sm.short_message);
			pdu->u.deliver_sm.short_message = NULL;
			pdu->u.deliver_sm.sm_length = 0;

			/* pass the message as a single pdu */
			msg_count = 1;
		}

		octstr_destroy(use_message_payload_meta);
	}

	if (msg_count == 1) {
		/* don't create split_parts of sms fit into one */
		gwlist_destroy(parts, msg_destroy_item);
		parts = NULL;
	}

	debug("smppServer", 0, "message length %ld, sending %ld message%s", octstr_len(msg->sms.msgdata), msg_count,
			msg_count == 1 ? "" : "s");

	if (parts) {
		while ((msg2 = gwlist_extract_first(parts)) != NULL) {
			pdu2 = smpp_pdu_create(deliver_sm, counter_increase(box->smpp_pdu_counter));
			pdu2->u.deliver_sm.source_addr_ton = pdu->u.deliver_sm.source_addr_ton;
			pdu2->u.deliver_sm.source_addr_npi = pdu->u.deliver_sm.source_addr_npi;
			pdu2->u.deliver_sm.dest_addr_ton = pdu->u.deliver_sm.dest_addr_ton;
			pdu2->u.deliver_sm.dest_addr_npi = pdu->u.deliver_sm.dest_addr_npi;
			pdu2->u.deliver_sm.data_coding = pdu->u.deliver_sm.data_coding;
			pdu2->u.deliver_sm.protocol_id = pdu->u.deliver_sm.protocol_id;
			pdu2->u.deliver_sm.source_addr = octstr_duplicate(
					pdu->u.deliver_sm.source_addr);
			pdu2->u.deliver_sm.destination_addr = octstr_duplicate(
					pdu->u.deliver_sm.destination_addr);
			pdu2->u.deliver_sm.service_type = octstr_duplicate(
					pdu->u.deliver_sm.service_type);

			/* the following condition is currently always true */
			/* uncomment in case we're doing a SAR-split instead */
			if (/*octstr_len(msg2->sms.udhdata) > 0*/1) {
				pdu2->u.deliver_sm.esm_class = pdu->u.deliver_sm.esm_class | ESM_CLASS_DELIVER_UDH_INDICATOR;
				pdu2->u.deliver_sm.short_message = octstr_cat(msg2->sms.udhdata, msg2->sms.msgdata);
			} else {
				pdu2->u.deliver_sm.short_message = octstr_duplicate(
						msg2->sms.msgdata);
			}

			if (box->version > 0x33) {
				dict_destroy(pdu2->u.deliver_sm.tlv);
				pdu2->u.deliver_sm.tlv = meta_data_get_values(msg->sms.meta_data, "smpp");
			}

			gwlist_append(pdulist, pdu2);
			msg_destroy(msg2);
		}

		smpp_pdu_destroy(pdu);
	} else {
		if (box->version > 0x33) {
			dict_destroy(pdu->u.deliver_sm.tlv);
			pdu->u.deliver_sm.tlv = NULL;
			pdu->u.deliver_sm.tlv = meta_data_get_values(msg->sms.meta_data, "smpp");
		}

		gwlist_append(pdulist, pdu);
	}

	return pdulist;
}

/*
 * Convert SMPP PDU to internal Msgs structure.
 * Return the Msg if all was fine and NULL otherwise, while getting
 * the failing reason delivered back in *reason.
 * XXX semantical check on the incoming values can be extended here.
 */
static Msg *pdu_to_msg(Boxc *box, SMPP_PDU *pdu, long *reason) {
	Msg *msg;
	int ton, npi;

	gw_assert(pdu->type == submit_sm);
	msg = msg_create(sms);
	gw_assert(msg != NULL);
	msg->sms.sms_type = mt_push;
	*reason = SMPP_ESME_ROK;

	/*
	 * Reset source addr to have a prefixed '+' in case we have an
	 * intl. TON to allow backend boxes (ie. smsbox) to distinguish
	 * between national and international numbers.
	 */
	ton = pdu->u.submit_sm.source_addr_ton;
	npi = pdu->u.submit_sm.source_addr_npi;
	/* check source addr */
	if ((*reason = convert_addr_from_pdu(box->boxc_id, pdu->u.submit_sm.source_addr, ton, npi)) != SMPP_ESME_ROK)
		goto error;
	msg->sms.sender = pdu->u.submit_sm.source_addr;
	pdu->u.submit_sm.source_addr = NULL;
	msg->sms.service = octstr_duplicate(box->sms_service);

	/*
	 * Follows SMPP spec. v3.4. issue 1.2
	 * it's not allowed to have destination_addr NULL
	 */
	if (pdu->u.submit_sm.destination_addr == NULL) {
		error(0, "SMPP[%s]: Mallformed destination_addr `%s', may not be empty. "
				"Discarding MO message.", octstr_get_cstr(box->boxc_id),
				octstr_get_cstr(pdu->u.submit_sm.destination_addr));
		*reason = SMPP_ESME_RINVDSTADR;
		goto error;
	}

	/* copy priority_flag into msg */
	if (pdu->u.submit_sm.priority_flag >= 0 && pdu->u.submit_sm.priority_flag <= 3) {
		msg->sms.priority = pdu->u.submit_sm.priority_flag;
	}

	/* Same reset of destination number as for source */
	ton = pdu->u.submit_sm.dest_addr_ton;
	npi = pdu->u.submit_sm.dest_addr_npi;
	/* check destination addr */
	if ((*reason = convert_addr_from_pdu(box->boxc_id, pdu->u.submit_sm.destination_addr, ton, npi)) != SMPP_ESME_ROK)
		goto error;
	msg->sms.receiver = pdu->u.submit_sm.destination_addr;
	pdu->u.submit_sm.destination_addr = NULL;

	/* SMSCs use service_type for billing information */
	msg->sms.binfo = pdu->u.submit_sm.service_type;
	pdu->u.submit_sm.service_type = NULL;

	if (pdu->u.submit_sm.esm_class & ESM_CLASS_SUBMIT_RPI)
		msg->sms.rpi = 1;

	/*
	 * Check for message_payload if version > 0x33 and sm_length == 0
	 * Note: SMPP spec. v3.4. doesn't allow to send both: message_payload & short_message!
	 */
	if (box->version > 0x33 && pdu->u.submit_sm.sm_length == 0 && pdu->u.submit_sm.message_payload) {
		msg->sms.msgdata = pdu->u.submit_sm.message_payload;
		pdu->u.submit_sm.message_payload = NULL;
	} else {
		msg->sms.msgdata = pdu->u.submit_sm.short_message;
		pdu->u.submit_sm.short_message = NULL;
	}

	/*
	 * Encode udh if udhi set
	 * for reference see GSM03.40, section 9.2.3.24
	 */
	if (pdu->u.submit_sm.esm_class & ESM_CLASS_SUBMIT_UDH_INDICATOR) {
		int udhl;
		udhl = octstr_get_char(msg->sms.msgdata, 0) + 1;
		debug("smppServer", 0, "SMPP[%s]: UDH length read as %d", octstr_get_cstr(box->boxc_id), udhl);
		if (udhl > octstr_len(msg->sms.msgdata)) {
			error(0, "SMPP[%s]: Mallformed UDH length indicator 0x%03x while message length "
					"0x%03lx. Discarding MO message.", octstr_get_cstr(box->boxc_id), udhl,
					octstr_len(msg->sms.msgdata));
			*reason = SMPP_ESME_RINVESMCLASS;
			goto error;
		}
		msg->sms.udhdata = octstr_copy(msg->sms.msgdata, 0, udhl);
		octstr_delete(msg->sms.msgdata, 0, udhl);
	}

	dcs_to_fields(&msg, pdu->u.submit_sm.data_coding);

	/* handle default data coding */
	switch (pdu->u.submit_sm.data_coding) {
	case 0x00: /* default SMSC alphabet */
		/*
		 * try to convert from something interesting if specified so
		 * unless it was specified binary, ie. UDH indicator was detected
		 */
		if (box->alt_charset && msg->sms.coding != DC_8BIT) {
			if (charset_convert(msg->sms.msgdata, octstr_get_cstr(box->alt_charset), "ISO-8859-1") != 0)
				error(0, "Failed to convert msgdata from charset <%s> to <%s>, will leave as is.",
						octstr_get_cstr(box->alt_charset), "ISO-8859-1");
			msg->sms.coding = DC_7BIT;
		} else { /* assume GSM 03.38 7-bit alphabet */
			charset_gsm_to_utf8(msg->sms.msgdata);
			msg->sms.coding = DC_7BIT;
		}
		break;
	case 0x01: /* ASCII or IA5 - not sure if I need to do anything */
	case 0x03: /* ISO-8859-1 - do nothing */
		msg->sms.coding = DC_7BIT;
		break;
	case 0x02: /* 8 bit binary - do nothing */
	case 0x04: /* 8 bit binary - do nothing */
		msg->sms.coding = DC_8BIT;
		break;
	case 0x05: /* JIS - what do I do with that ? */
		break;
	case 0x06: /* Cyrllic - iso-8859-5, I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-5", "UCS-2BE") != 0)
			error(0, "Failed to convert msgdata from cyrllic to UCS-2, will leave as is");
		msg->sms.coding = DC_UCS2;
		break;
	case 0x07: /* Hebrew iso-8859-8, I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-8", "UCS-2BE") != 0)
			error(0, "Failed to convert msgdata from hebrew to UCS-2, will leave as is");
		msg->sms.coding = DC_UCS2;
		break;
	case 0x08: /* unicode UCS-2, yey */
		msg->sms.coding = DC_UCS2;
		break;

		/*
		 * don't much care about the others,
		 * you implement them if you feel like it
		 */

	default:
		/*
		 * some of smsc send with dcs from GSM 03.38 , but these are reserved in smpp spec.
		 * So we just look decoded values from dcs_to_fields and if none there make our assumptions.
		 * if we have an UDH indicator, we assume DC_8BIT.
		 */
		if (msg->sms.coding == DC_UNDEF && pdu->u.submit_sm.esm_class & ESM_CLASS_SUBMIT_UDH_INDICATOR)
			msg->sms.coding = DC_8BIT;
		else if (msg->sms.coding == DC_7BIT || msg->sms.coding == DC_UNDEF) { /* assume GSM 7Bit , reencode */
			msg->sms.coding = DC_7BIT;
			charset_gsm_to_utf8(msg->sms.msgdata);
		}
	}
	msg->sms.pid = pdu->u.submit_sm.protocol_id;
	/* set priority flag */
	msg->sms.priority = pdu->u.submit_sm.priority_flag;

	/* ask for the delivery reports if needed */
	switch (pdu->u.submit_sm.registered_delivery & 0x03) {
	case 1:
		msg->sms.dlr_mask = (DLR_SUCCESS | DLR_FAIL | DLR_SMSC_FAIL);
		break;
	case 2:
		msg->sms.dlr_mask = (DLR_FAIL | DLR_SMSC_FAIL);
		break;
	default:
		msg->sms.dlr_mask = 0;
		break;
	}
	if (pdu->u.submit_sm.esm_class & (0x04 | 0x08)) {
		msg->sms.sms_type = report_mo;
	}

	if (box->version > 0x33) {
		if (msg->sms.meta_data == NULL)
			msg->sms.meta_data = octstr_create("");
		meta_data_set_values(msg->sms.meta_data, pdu->u.submit_sm.tlv, "smpp", 1);
	}

	msg->sms.time = time(NULL);

	/* set validity period if needed */
	if (pdu->u.submit_sm.validity_period) {
		msg->sms.validity = timestamp_to_minutes(pdu->u.submit_sm.validity_period);
	}

	/* set schedule delivery time if needed */
	if (pdu->u.submit_sm.schedule_delivery_time) {
		msg->sms.deferred = timestamp_to_minutes(pdu->u.submit_sm.schedule_delivery_time);
	}

	return msg;

	error: msg_destroy(msg);
	return NULL;
}

/*
 * Convert SMPP PDU to internal Msgs structure.
 * Return the Msg if all was fine and NULL otherwise, while getting
 * the failing reason delivered back in *reason.
 * XXX semantical check on the incoming values can be extended here.
 */
static Msg *data_sm_to_msg(Boxc *box, SMPP_PDU *pdu, long *reason) {
	Msg *msg;
	int ton, npi;

	gw_assert(pdu->type == data_sm);

	msg = msg_create(sms);
	gw_assert(msg != NULL);
	msg->sms.sms_type = mt_push;
	*reason = SMPP_ESME_ROK;

	/*
	 * Reset source addr to have a prefixed '+' in case we have an
	 * intl. TON to allow backend boxes (ie. smsbox) to distinguish
	 * between national and international numbers.
	 */
	ton = pdu->u.data_sm.source_addr_ton;
	npi = pdu->u.data_sm.source_addr_npi;
	/* check source addr */
	if ((*reason = convert_addr_from_pdu(box->boxc_id, pdu->u.data_sm.source_addr, ton, npi)) != SMPP_ESME_ROK)
		goto error;
	msg->sms.sender = pdu->u.data_sm.source_addr;
	pdu->u.data_sm.source_addr = NULL;

	/*
	 * Follows SMPP spec. v3.4. issue 1.2
	 * it's not allowed to have destination_addr NULL
	 */
	if (pdu->u.data_sm.destination_addr == NULL) {
		error(0, "SMPP[%s]: Mallformed destination_addr `%s', may not be empty. "
				"Discarding MO message.", octstr_get_cstr(box->boxc_id),
				octstr_get_cstr(pdu->u.data_sm.destination_addr));
		*reason = SMPP_ESME_RINVDSTADR;
		goto error;
	}

	/* Same reset of destination number as for source */
	ton = pdu->u.data_sm.dest_addr_ton;
	npi = pdu->u.data_sm.dest_addr_npi;
	/* check destination addr */
	if ((*reason = convert_addr_from_pdu(box->boxc_id, pdu->u.data_sm.destination_addr, ton, npi)) != SMPP_ESME_ROK)
		goto error;
	msg->sms.receiver = pdu->u.data_sm.destination_addr;
	pdu->u.data_sm.destination_addr = NULL;

	/* SMSCs use service_type for billing information */
	msg->sms.binfo = pdu->u.data_sm.service_type;
	pdu->u.data_sm.service_type = NULL;

	if (pdu->u.data_sm.esm_class & ESM_CLASS_SUBMIT_RPI)
		msg->sms.rpi = 1;

	msg->sms.msgdata = pdu->u.data_sm.message_payload;
	pdu->u.data_sm.message_payload = NULL;

	/*
	 * Encode udh if udhi set
	 * for reference see GSM03.40, section 9.2.3.24
	 */
	if (pdu->u.data_sm.esm_class & ESM_CLASS_SUBMIT_UDH_INDICATOR) {
		int udhl;
		udhl = octstr_get_char(msg->sms.msgdata, 0) + 1;
		debug("smppServer", 0, "SMPP[%s]: UDH length read as %d", octstr_get_cstr(box->boxc_id), udhl);
		if (udhl > octstr_len(msg->sms.msgdata)) {
			error(0, "SMPP[%s]: Mallformed UDH length indicator 0x%03x while message length "
					"0x%03lx. Discarding MO message.", octstr_get_cstr(box->boxc_id), udhl,
					octstr_len(msg->sms.msgdata));
			*reason = SMPP_ESME_RINVESMCLASS;
			goto error;
		}
		msg->sms.udhdata = octstr_copy(msg->sms.msgdata, 0, udhl);
		octstr_delete(msg->sms.msgdata, 0, udhl);
	}

	dcs_to_fields(&msg, pdu->u.data_sm.data_coding);

	/* handle default data coding */
	switch (pdu->u.data_sm.data_coding) {
	case 0x00: /* default SMSC alphabet */
		/*
		 * try to convert from something interesting if specified so
		 * unless it was specified binary, ie. UDH indicator was detected
		 */
		if (box->alt_charset && msg->sms.coding != DC_8BIT) {
			if (charset_convert(msg->sms.msgdata, octstr_get_cstr(box->alt_charset), "ISO-8859-1") != 0)
				error(0, "Failed to convert msgdata from charset <%s> to <%s>, will leave as is.",
						octstr_get_cstr(box->alt_charset), "ISO-8859-1");
			msg->sms.coding = DC_7BIT;
		} else { /* assume GSM 03.38 7-bit alphabet */
			charset_gsm_to_utf8(msg->sms.msgdata);
			msg->sms.coding = DC_7BIT;
		}
		break;
	case 0x01: /* ASCII or IA5 - not sure if I need to do anything */
	case 0x03: /* ISO-8859-1 - do nothing */
		msg->sms.coding = DC_7BIT;
		break;
	case 0x02: /* 8 bit binary - do nothing */
	case 0x04: /* 8 bit binary - do nothing */
		msg->sms.coding = DC_8BIT;
		break;
	case 0x05: /* JIS - what do I do with that ? */
		break;
	case 0x06: /* Cyrllic - iso-8859-5, I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-5", "UCS-2BE") != 0)
			error(0, "Failed to convert msgdata from cyrllic to UCS-2, will leave as is");
		msg->sms.coding = DC_UCS2;
		break;
	case 0x07: /* Hebrew iso-8859-8, I'll convert to unicode */
		if (charset_convert(msg->sms.msgdata, "ISO-8859-8", "UCS-2BE") != 0)
			error(0, "Failed to convert msgdata from hebrew to UCS-2, will leave as is");
		msg->sms.coding = DC_UCS2;
		break;
	case 0x08: /* unicode UCS-2, yey */
		msg->sms.coding = DC_UCS2;
		break;

		/*
		 * don't much care about the others,
		 * you implement them if you feel like it
		 */

	default:
		/*
		 * some of smsc send with dcs from GSM 03.38 , but these are reserved in smpp spec.
		 * So we just look decoded values from dcs_to_fields and if none there make our assumptions.
		 * if we have an UDH indicator, we assume DC_8BIT.
		 */
		if (msg->sms.coding == DC_UNDEF && pdu->u.data_sm.esm_class & ESM_CLASS_SUBMIT_UDH_INDICATOR)
			msg->sms.coding = DC_8BIT;
		else if (msg->sms.coding == DC_7BIT || msg->sms.coding == DC_UNDEF) { /* assume GSM 7Bit , reencode */
			msg->sms.coding = DC_7BIT;
			charset_gsm_to_utf8(msg->sms.msgdata);
		}
	}

	if (box->version > 0x33) {
		if (msg->sms.meta_data == NULL)
			msg->sms.meta_data = octstr_create("");
		meta_data_set_values(msg->sms.meta_data, pdu->u.data_sm.tlv, "smpp", 1);
	}

	msg->sms.time = time(NULL);

	return msg;

	error: msg_destroy(msg);
	return NULL;
}

Octstr *concat_msgids(Octstr *msgid, List *list) {
	Octstr *ret = octstr_duplicate(msgid);
	int i;
	Msg *msg;

	for (i = 0; i < gwlist_len(list); i++) {
		msg = gwlist_get(list, i);
		octstr_append(ret, octstr_imm(";"));
		octstr_append(ret, msg->sms.dlr_url);
	}
	return ret;
}

void check_multipart(Boxc *box, Msg *msg, int *msg_to_send, Msg **msg2, List **parts_list) {
	int reference, total;
	Octstr *key;

	if (msg->sms.udhdata && octstr_len(msg->sms.udhdata) == 6 && octstr_get_char(msg->sms.udhdata, 1) == 0) {
		/* We collect long messages as one and send them to bearerbox as a whole, so they can be sent
		 from the same smsc. */
		(*msg_to_send) = 0;
		debug("smppServer", 0, "assemble multi-part message.");
		reference = octstr_get_char(msg->sms.udhdata, 3);
		total = octstr_get_char(msg->sms.udhdata, 4);
		key = octstr_format("%S-%i", msg->sms.receiver, reference);
		(*parts_list) = dict_get(list_dict, key);
		if (NULL == (*parts_list)) {
			(*parts_list) = gwlist_create();
			dict_put(list_dict, key, (*parts_list));
		}
		debug("smppServer", 0, "received %ld of %d.", gwlist_len((*parts_list)) + 1, total);
		if ((gwlist_len((*parts_list)) + 1) == total) {
			debug("smppServer", 0, "received all parts of multi-part message.");
			gwlist_append((*parts_list), msg);
			/* assemble message */
			(*msg2) = catenate_msg((*parts_list), total);
			dict_put(list_dict, key, NULL);
			octstr_destroy(key);
			if (NULL == (*msg2)) {
				/* we could not assemble an appropiate message */
				debug("smppServer", 0, "Invalid multi-part message.");

			} else {
//				(*msg2)->sms.smsc_id = box->route_to_smsc ? octstr_duplicate(box->route_to_smsc) : NULL;
				(*msg2)->sms.boxc_id = octstr_duplicate(box->boxc_id);
				debug("smppServer", 0, "multi-part message, length: %ld.", octstr_len((*msg2)->sms.msgdata));
				(*msg_to_send) = 1;
			}
		} else {
			gwlist_append((*parts_list), msg);
			octstr_destroy(key);
		}
	}
}

static void sql_to_smpp(void *arg) {
	Boxc *box = NULL;
	SMPP_PDU *pdu = NULL;
	Octstr *msgid = NULL;
	MYSQL_RES *result = NULL;
	MYSQL_ROW row = NULL;
	box = arg;
	info(0, "smppServer: sql_to_smpp: thread starts");
	while (smppbox_status == SMPP_RUNNING && box->alive) {
		if (box->login_type == SMPP_LOGIN_TRANSCEIVER || box->login_type == SMPP_LOGIN_RECEIVER) {

			result = mysql_select(octstr_format(SQL_SELECT_MO,octstr_get_cstr(integratorQueueId)));
			int num_rows = mysql_num_rows(result);
			debug("smppServer", 0, "%i messages in the queue", num_rows);
			while ((row = mysql_fetch_row(result))) {
				debug("smppServer", 0, "%s", row[0]);
				pdu = smpp_pdu_create(deliver_sm, counter_increase(box->smpp_pdu_counter));
				pdu->u.deliver_sm.source_addr = octstr_imm(row[1]);
				pdu->u.deliver_sm.destination_addr = octstr_imm(row[2]);
				pdu->u.deliver_sm.short_message = octstr_imm(row[7]);
				msgid = octstr_format("%ld", pdu->u.deliver_sm.sequence_number);
				dict_put(box->deliver_acks, msgid, row[0]);

				if (send_pdu(box->smpp_connection, box->boxc_id, pdu) == -1) {
					mysql_update(octstr_format(SQL_UPDATE_MO_STATUS, "NOTDISPATCHED", row[0]));
				} else {
					mysql_update(octstr_format(SQL_UPDATE_MO_STATUS, "DISPATCHED", row[0]));
				}
				smpp_pdu_destroy(pdu);
				info(0, "Enviado");
			}
			mysql_free_result(result);


		}
		gwthread_sleep(5);
	}

	info(0, "smppServer: sql_to_smpp: thread terminates");
	//smppbox_status = SMPP_SHUTDOWN;
}

static CarrierRoute *carrierRouteCreate(){
	CarrierRoute *route;
	route= gw_malloc(sizeof(CarrierRoute));
	route->id=NULL;
	route->name=NULL;
	route->preffix=NULL;
	route->errorCode=0;
	route->errorText=NULL;
	return route;
}

static void carrierRouteDestroy(CarrierRoute *route) {
	if (route == NULL)
		return;
	if (route->id)
		octstr_destroy(route->id);
	if (route->name)
		octstr_destroy(route->name);
	if (route->preffix)
		octstr_destroy(route->preffix);
	if (route->errorText)
			octstr_destroy(route->errorText);
	gw_free(route);
}

static Service *serviceCreate(){
	Service *service;
	service= gw_malloc(sizeof(Service));
	service->id=NULL;
	service->name=NULL;
	service->connectionId=NULL;

	return service;
}

static void serviceDestroy(Service *service) {
	if (service == NULL)
		return;
	if (service->id)
		octstr_destroy(service->id);
	if (service->name)
		octstr_destroy(service->name);
	if (service->connectionId)
			octstr_destroy(service->connectionId);

	gw_free(service);
}

#define st_num(x) (stuffer[stuffcount++] = get_numeric_value_or_return_null(x))
#define st_str(x) (stuffer[stuffcount++] = get_string_value_or_return_null(x))
static void handle_pdu(Connection *conn, Boxc *box, SMPP_PDU *pdu) {
	SMPP_PDU *resp = NULL;
	Msg *msg = NULL, *msg2 = NULL, *mack = NULL;
	long reason;
	Octstr *msgid = NULL, *hold_service = NULL, *system_type = NULL;
	char *correlation_id = NULL;
	int msg_to_send = 1;
	List *parts_list = NULL;
	char id[UUID_STR_LEN + 1];
	Octstr *stuffer[30];
	int stuffcount = 0;

	dump_pdu("Got PDU:", box->boxc_id, pdu);
	switch (pdu->type) {
	case bind_transmitter:
	case bind_receiver:
	case bind_transceiver:
		break;
	default:
		if (!box->logged_in) {
			resp = smpp_pdu_create(generic_nack, pdu->u.generic_nack.sequence_number);
			resp->u.generic_nack.command_status = SMPP_ESME_RINVPASWD;
			goto error;
		}
		break;
	}
	switch (pdu->type) {
	/* We set a substitute box id here, if smppbox id is used*/
	case bind_transmitter:
		debug("smppServer", 0, "Got bind_transmitter");
		system_type = pdu->u.bind_transmitter.system_type ? pdu->u.bind_transmitter.system_type : octstr_imm("");
		if (transmitter_mode == 1
				&& check_login(box, pdu->u.bind_transmitter.system_id, pdu->u.bind_transmitter.password, system_type,
						SMPP_LOGIN_TRANSMITTER)) {
			debug("smppServer", 0, "Check login was success");
			box->logged_in = 1;
			box->version = pdu->u.bind_transmitter.interface_version;
			box->login_type = SMPP_LOGIN_TRANSMITTER;
			box->boxc_id = octstr_duplicate(system_type);
			box->sms_service = octstr_duplicate(
					pdu->u.bind_transmitter.system_id);
			resp = smpp_pdu_create(bind_transmitter_resp, pdu->u.bind_transmitter.sequence_number);
			resp->u.bind_transmitter_resp.system_id = octstr_duplicate(
					our_system_id);
			debug("smppServer", 0, "Client connected with id %s", octstr_get_cstr(box->boxc_id));
		} else {
			debug("smppServer", 0, "Check login failure");
			resp = smpp_pdu_create(bind_transmitter_resp, pdu->u.bind_transmitter_resp.sequence_number);
			resp->u.bind_transmitter.command_status = 0x0d; /* invalid login */
			box->alive = 0;
		}
		break;
	case bind_receiver:
		debug("smppServer", 0, "Got bind_receiver");
		system_type = pdu->u.bind_receiver.system_type ? pdu->u.bind_receiver.system_type : octstr_imm("");
		if (receiver_mode == 1
				&& check_login(box, pdu->u.bind_receiver.system_id, pdu->u.bind_receiver.password, system_type,
						SMPP_LOGIN_RECEIVER)) {
			debug("smppServer", 0, "Check login success");
			box->logged_in = 1;
			box->version = pdu->u.bind_receiver.interface_version;
			box->login_type = SMPP_LOGIN_RECEIVER;
			box->boxc_id = octstr_duplicate(system_type);
			box->sms_service = octstr_duplicate(pdu->u.bind_receiver.system_id);
			resp = smpp_pdu_create(bind_receiver_resp, pdu->u.bind_receiver.sequence_number);
			resp->u.bind_receiver_resp.system_id = octstr_duplicate(
					our_system_id);
			debug("smppServer", 0, "Client connected with id %s", octstr_get_cstr(box->boxc_id));
		} else {
			debug("smppServer", 0, "Check login failure");
			resp = smpp_pdu_create(bind_receiver_resp, pdu->u.bind_receiver.sequence_number);
			resp->u.bind_receiver_resp.command_status = 0x0d; /* invalid login */
			box->alive = 0;
		}
		break;
	case bind_transceiver:
		debug("smppServer", 0, "Got bind_receiver");
		system_type = pdu->u.bind_transceiver.system_type ? pdu->u.bind_transceiver.system_type : octstr_imm("");
		if (check_login(box, pdu->u.bind_transceiver.system_id, pdu->u.bind_transceiver.password, system_type,
				SMPP_LOGIN_TRANSCEIVER)) {
			debug("smppServer", 0, "Check login success");
			box->logged_in = 1;
			box->version = pdu->u.bind_transceiver.interface_version;
			box->login_type = SMPP_LOGIN_TRANSCEIVER;
			box->boxc_id = octstr_duplicate(system_type);
			box->sms_service = octstr_duplicate(
					pdu->u.bind_transceiver.system_id);
			resp = smpp_pdu_create(bind_transceiver_resp, pdu->u.bind_transceiver.sequence_number);
			resp->u.bind_transceiver_resp.system_id = octstr_duplicate(
					our_system_id);
			debug("smppServer", 0, "Client connected with id %s", octstr_get_cstr(box->boxc_id));
		} else {
			debug("smppServer", 0, "Check login failure");
			resp = smpp_pdu_create(bind_transceiver_resp, pdu->u.bind_transceiver.sequence_number);
			resp->u.bind_transceiver_resp.command_status = 0x0d; /* invalid login */
		}
		break;
	case unbind:
		resp = smpp_pdu_create(unbind_resp, pdu->u.unbind.sequence_number);
		box->logged_in = 0;
		box->alive = 0;
		break;
	case enquire_link:
		resp = smpp_pdu_create(enquire_link_resp, pdu->u.enquire_link.sequence_number);
		break;
	case data_sm:
		msg = data_sm_to_msg(box, pdu, &reason);
		msg2 = msg;
		if (msg == NULL) {
			resp = smpp_pdu_create(generic_nack, pdu->u.data_sm.sequence_number);
			resp->u.generic_nack.command_status = SMPP_ESME_RUNKNOWNERR;
		} else {
			check_multipart(box, msg, &msg_to_send, &msg2, &parts_list);
//			msg->sms.smsc_id = box->route_to_smsc ? octstr_duplicate(box->route_to_smsc) : NULL;
			msg->sms.boxc_id = octstr_duplicate(box->boxc_id);
			resp = smpp_pdu_create(data_sm_resp, pdu->u.data_sm.sequence_number);
			msgid = generate_smppid(msg);
			msg->sms.dlr_url = octstr_duplicate(msgid);
			resp->u.data_sm_resp.message_id = msgid;

		}
		break;
	case submit_sm:
		msg = pdu_to_msg(box, pdu, &reason);
		msg2 = msg;
		if (msg == NULL) {
			resp = smpp_pdu_create(generic_nack, pdu->u.submit_sm.sequence_number);
			resp->u.generic_nack.command_status = SMPP_ESME_RUNKNOWNERR;
		} else {
			check_multipart(box, msg, &msg_to_send, &msg2, &parts_list);
//			msg->sms.smsc_id = box->route_to_smsc ? octstr_duplicate(box->route_to_smsc) : NULL;

			msg->sms.boxc_id = octstr_duplicate(box->boxc_id);
			resp = smpp_pdu_create(submit_sm_resp, pdu->u.submit_sm.sequence_number);
			msgid = generate_smppid(msg);
			//msg->sms.dlr_url = octstr_duplicate(msgid);
			resp->u.submit_sm_resp.message_id = octstr_duplicate(msgid);
			CarrierRoute *route;
			route=carrierRouteCreate();

			if (enRouteMessage(msg->sms.receiver, route)) {
				Service *service;
				service=serviceCreate();
				if (searchService(route, service,msg->sms.sender)) {
					//Buscar Servicio
					mysql_update(
							octstr_format(SQL_INSERT_MT, msg->sms.receiver,
									msg->sms.sender, "0", msg->sms.msgdata, "0",
									msgid, "QUEUED", route->errorCode,
									route->errorText, service->id,
									service->name, route->id,
									integratorId, integratorQueueId,service->connectionId));
				} else {
					debug("smppServer",0,"No existe servicio");
					mysql_update(
							octstr_format(SQL_INSERT_MT, msg->sms.receiver,
									msg->sms.sender, "0", msg->sms.msgdata, "0",
									msgid, "NOTDISPATCHED", route->errorCode,
									route->errorText, service->id,
									service->name, route->id,
									integratorId, integratorQueueId,service->connectionId));
				}
				serviceDestroy(service);

			} else {
				mysql_update(
						octstr_format(SQL_INSERT_MT, msg->sms.receiver,
								msg->sms.sender, "0", msg->sms.msgdata, "0",
								msgid, "'NOTDISPATCHED'", route->errorCode,
								route->errorText, "NULL", "NULL", route->id,
								 integratorId,
								integratorQueueId,"NULL"));

			}

			carrierRouteDestroy(route);

		}
		break;
		/* Note that deliver_sm_resp message_id filed is set to NULL. Instead, the sequwnce number
		 * is used for identification. */
	case deliver_sm_resp:
		msgid = octstr_format("%ld", pdu->u.deliver_sm_resp.sequence_number);
		correlation_id = dict_get(box->deliver_acks, msgid);
		debug("", 0, "codigo %s", correlation_id);
		mysql_update(octstr_format(SQL_UPDATE_MO_STATUS, "CONFIRMED", correlation_id));
		if (mack) {
			msg = msg_duplicate(mack);
			/* TODO: ack_failed_tmp */
			if (pdu->u.deliver_sm_resp.command_status != 0) {
				msg->ack.nack = ack_failed;
			}
			dict_put(box->deliver_acks, msgid, NULL); /* would destroy the message */
		}

		octstr_destroy(msgid);
		msgid = NULL;
		break;
	case unbind_resp:
		box->logged_in = 0;
		box->alive = 0;
		break;
	default:
		error(0, "SMPP[%s]: Unknown PDU type 0x%08lx, ignored.", octstr_get_cstr(box->boxc_id), pdu->type);
		/*
		 send gnack , see smpp3.4 spec., section 3.3
		 because we doesn't know what kind of pdu received, we assume generick_nack_resp
		 (header always the same)
		 */
		resp = smpp_pdu_create(generic_nack, pdu->u.generic_nack.sequence_number);
		resp->u.generic_nack.command_status = SMPP_ESME_RINVCMDID;
		break;
	}
	/* An intentional fall-through*/
	error:

	smpp_pdu_destroy(pdu);
	if (resp != NULL) {
		info(0, "Sending PDU");
		send_pdu(conn, box->boxc_id, resp);
	}
	smpp_pdu_destroy(resp);
}

int enRouteMessage(Octstr *phoneNumber,CarrierRoute *route) {
	if (searchBlackList(phoneNumber,route)) {
		debug("smppServer",0,"Phone Number %s is in black list",octstr_get_cstr(phoneNumber));
		return 1;
	}
	debug("smppServer",0,"Phone Number %s is not in black list",octstr_get_cstr(phoneNumber));
	if (searchPortedNumber(phoneNumber,route)) {
		//Busqueda por Portados
		debug("smppServer",0,"Phone Number %s is a ported number",octstr_get_cstr(phoneNumber));
		return 1;
	}
	debug("smppServer",0,"Phone Number %s is not a ported number",octstr_get_cstr(phoneNumber));
	//Busqueda por Prefijos
	int j;
	for (j = 0; j < numberCarrierRoutes; j++) {
		int match = does_prefix_match(carrierRoutes[j].preffix, phoneNumber);
		if (match) {
			route->id = carrierRoutes[j].id;
			route->name=carrierRoutes[j].name;
			route->preffix=carrierRoutes[j].preffix;
			route->errorCode=0;
			route->errorText=octstr_format("");
			debug("smppServer",0,"Message route to %s",octstr_get_cstr(route->name));
			return 1;
		}

	}
	route->errorCode=1012;
	route->errorText=octstr_format("No route to Phone Number %s",octstr_get_cstr(phoneNumber));
	return 0;
}

int searchBlackList(Octstr *phoneNumber,CarrierRoute *route) {
	Octstr *sql;
	MYSQL_RES *res;
	MYSQL_ROW row;

	int result;

	sql = octstr_format(SQL_SELECT_BLACK_LIST, octstr_get_cstr(phoneNumber));
	res = mysql_select(sql);

	if (res == NULL) {
		debug("SQLBOX", 0, "SQL statement failed: %s", octstr_get_cstr(sql));
	} else {
		if (mysql_num_rows(res) >= 1) {
			row = mysql_fetch_row(res);
			route->id = octstr_format("NULL");
			route->errorCode = 1010;
			route->errorText = octstr_format("Phone Number %S is in black list",
					phoneNumber);
			result = 1;
		} else {
			route->errorCode = 0;
			route->errorText = octstr_format("");
			result = 0;
		}
		mysql_free_result(res);
	}
	octstr_destroy(sql);
	return result;

}


int searchPortedNumber(Octstr *phoneNumber,CarrierRoute *route)
{
	Octstr *sql;
	MYSQL_RES *res;
	MYSQL_ROW row;
	int result;

	sql = octstr_format(SQL_SELECT_PORTED_NUMBER, octstr_get_cstr(phoneNumber));
	res = mysql_select(sql);

	if (res == NULL)
	{
		debug("SQLBOX", 0, "SQL statement failed: %s", octstr_get_cstr(sql));
	}
	else
	{
		if (mysql_num_rows(res) >= 1)
		{
			row = mysql_fetch_row(res);
			route->id=octstr_imm(row[0]);
			route->errorCode=0;
			route->errorText=octstr_format("");
			debug("smppServer",0,"%S",route->id);
			result=1;
		}
		else{
			route->errorCode=1011;
			route->errorText=octstr_format("Is not a ported number");
			result=0;
		}
		mysql_free_result(res);
	}
	octstr_destroy(sql);
	return result;
}

int searchService(CarrierRoute *route,Service *service,Octstr *shortNumber) {
	Octstr *sql;
	MYSQL_RES *res;
	MYSQL_ROW row;

	int result;

	sql = octstr_format(SQL_SELECT_SERVICE,octstr_get_cstr(shortNumber), octstr_get_cstr(route->id),octstr_get_cstr(integratorId),octstr_get_cstr(integratorQueueId));
	res = mysql_select(sql);

	if (res == NULL) {
		debug("SQLBOX", 0, "SQL statement failed: %s", octstr_get_cstr(sql));
	} else {
		if (mysql_num_rows(res) >= 1) {
			row = mysql_fetch_row(res);
			service->id = octstr_imm(row[0]);
			service->name = octstr_imm(row[1]);
			service->connectionId = octstr_imm(row[2]);
			result = 1;
		} else {
			route->errorCode = 1012;
			route->errorText = octstr_format("No service to the message");
			result = 0;
		}
		mysql_free_result(res);
	}
	octstr_destroy(sql);
	return result;

}

static Octstr *get_numeric_value_or_return_null(long int num) {
	if (num == -1) {
		return octstr_create("NULL");
	}
	return octstr_format("%ld", num);
}

static Octstr *get_string_value_or_return_null(Octstr *str) {
	if (str == NULL) {
		return octstr_create("NULL");
	}
	if (octstr_compare(str, octstr_imm("")) == 0) {
		return octstr_create("NULL");
	}
	octstr_replace(str, octstr_imm("\\"), octstr_imm("\\\\"));
	octstr_replace(str, octstr_imm("\'"), octstr_imm("\\\'"));
	return octstr_format("\'%S\'", str);
}
/*
 *-------------------------------------------------
 *  sender thingies
 *-------------------------------------------------
 *
 */



static Boxc *boxc_create(int fd, Octstr *ip, int ssl) {
	Boxc *boxc;

	boxc = gw_malloc(sizeof(Boxc));
	boxc->logged_in = 0;
	boxc->load = 0;
	boxc->smpp_connection = conn_wrap_fd(fd, ssl);
	boxc->client_ip = octstr_duplicate(ip);
	boxc->alive = 1;
	boxc->connect_time = time(NULL);
	boxc->boxc_id = NULL;
	boxc->sms_service = NULL;
	boxc->routable = 0;
	boxc->smpp_pdu_counter = counter_create();
	boxc->alt_charset = NULL; /* todo: get from config */
	boxc->version = 0x33; /* default value, set upon receiving a bind */
	boxc->msg_acks = dict_create(256, smpp_pdu_destroy_item);
	boxc->deliver_acks = dict_create(256, msg_destroy_item);
	boxc->service_type = NULL;
	boxc->source_addr_ton = smpp_source_addr_ton;
	boxc->source_addr_npi = smpp_source_addr_npi;
	boxc->autodetect_addr = smpp_autodetect_addr;
	boxc->dest_addr_ton = smpp_dest_addr_ton;
	boxc->dest_addr_npi = smpp_dest_addr_npi;
	boxc->alt_dcs = 0;
	boxc->validityperiod = -1;
	boxc->priority = 0;
	boxc->mo_recode = 0;

	return boxc;
}

static void boxc_destroy(Boxc *boxc) {
	if (boxc == NULL)
		return;
	/* do nothing to the lists, as they are only references */
	if (boxc->smpp_connection)
		conn_destroy(boxc->smpp_connection);
	if (boxc->boxc_id)
		octstr_destroy(boxc->boxc_id);
	if (boxc->alt_charset)
		octstr_destroy(boxc->alt_charset);
	if (boxc->client_ip)
		octstr_destroy(boxc->client_ip);
	if (boxc->sms_service)
		octstr_destroy(boxc->sms_service);

	dict_destroy(boxc->msg_acks);
	dict_destroy(boxc->deliver_acks);
	gw_free(boxc);
}

/* ------------------------------------------------------------------
 * SMPP thingies
 * ------------------------------------------------------------------
 */

/* generally, SMPP connections are always non-encrypted. */
static Boxc *accept_smpp(int fd, int ssl) {
	Boxc *newconn;
	Octstr *ip;

	int newfd;
	struct sockaddr_in client_addr;
	socklen_t client_addr_len;

	client_addr_len = sizeof(client_addr);

	newfd = accept(fd, (struct sockaddr *) &client_addr, &client_addr_len);
	if (newfd < 0)
		return NULL;

	ip = host_ip(client_addr);

	newconn = boxc_create(newfd, ip, 0);
	info(0, "Client connected from <%s>", octstr_get_cstr(ip));
	octstr_destroy(ip);

	return newconn;
}

static void smpp_to_sql(void *arg) {

	Boxc *box = arg;
	Connection *conn = box->smpp_connection;
	SMPP_PDU *pdu;
	long len;

	info(0, "smppServer: smpp_to_sql: thread starts");
	box->last_pdu_received = time(NULL);

	while (smppbox_status == SMPP_RUNNING && box->alive) {
		len = 0;
		switch (read_pdu(box, conn, &len, &pdu)) {
		case -1:
			error(0, "Invalid SMPP PDU received.");
			box->alive = 0;
			break;
		case 0:
			// idling
//			if (time(NULL) - box->last_pdu_received > smpp_timeout) {
//				box->alive = 0;
//			}
			gwthread_sleep(1);
			break;
		case 1:
			box->last_pdu_received = time(NULL);
			handle_pdu(conn, box, pdu);
			break;
		}
	}

	info(0, "smppServer: smpp_to_sql: thread terminates");
}

static void run_smppbox(void *arg) {
	int fd;
	Boxc *newconn;
	long sender, receiver;

	fd = (int) arg;
	newconn = accept_smpp(fd, 0);
	if (newconn == NULL) {
		panic(0, "Socket accept failed");
		return;
	}

	sender = gwthread_create(smpp_to_sql, newconn);
	debug("smppServer", 0, "smpp_to_sql created");
	if (sender == -1) {
		error(0, "Failed to start a new thread, disconnecting client <%s>", octstr_get_cstr(newconn->client_ip));
		boxc_destroy(newconn);
		return;
	}

//	sql_to_smpp(newconn);
	receiver = gwthread_create(sql_to_smpp, newconn);
	debug("smppServer", 0, "sql_to_smpp created");
	if (receiver == -1) {
		error(0, "Failed to start a new thread, disconnecting client <%s>", octstr_get_cstr(newconn->client_ip));
		boxc_destroy(newconn);
		return;
	}
	info(0, "Join sender");
	gwthread_join(sender);

	info(0, "Join receiver");
	gwthread_join(receiver);

//	gwlist_delete_equal(all_boxes, newconn);
	boxc_destroy(newconn);
}

static void wait_for_connections(int fd, void (*function)(void *arg), List *waited) {
	int ret = 0;
	int timeout = 10; /* 10 sec. */

	gw_assert(function != NULL);

	while (smppbox_status == SMPP_RUNNING) {
		ret = gwthread_pollfd(fd, POLLIN, 1.0);
		if (smppbox_status == SMPP_SHUTDOWN) {
			if (ret == -1 || !timeout)
				break;
			else
				timeout--;
		}

		if (ret > 0) {
			debug("smppServer", 0, "ret is more than 0 ret: %d", ret);
			gwthread_create(function, (void *) fd);
			gwthread_sleep(1.0);
		} else if (ret < 0) {
			debug("smppServer", 0, "ret is less than 0 ret: %d", ret);
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN)
				continue;
			error(errno, "wait_for_connections failed");
		}
	}
}

static void smpp_server_box_run(void *arg) {
	int fd;
	int port;

	port = (int) arg;

	fd = make_server_socket(port, NULL);
	/* XXX add interface_name if required */

	if (fd < 0) {
		panic(0, "Could not open smppServer port %d", port);
	}

	/*
	 * infinitely wait for new connections;
	 * to shut down the system, SIGTERM is send and then
	 * select drops with error, so we can check the status
	 */

	info(0, "Waiting for SMPP connections on port %d.", port);
	wait_for_connections(fd, run_smppbox, NULL);
	info(0, "No more waiting for SMPP connections.");

	/* close listen socket */
	close(fd);
}

/***********************************************************************
 * Main program. Configuration, signal handling, etc.
 */

static void signal_handler(int signum) {
	/* On some implementations (i.e. linuxthreads), signals are delivered
	 * to all threads.  We only want to handle each signal once for the
	 * entire box, and we let the gwthread wrapper take care of choosing
	 * one.
	 */
	if (!gwthread_shouldhandlesignal(signum))
		return;

	switch (signum) {
	case SIGINT:
	case SIGTERM:
		if (smppbox_status == SMPP_RUNNING) {
			error(0, "SIGINT received, aborting program...");
			smppbox_status = SMPP_SHUTDOWN;
			debug("smppServer", 0, "server is running with smppbox_status %d", smppbox_status);
			gwthread_wakeup_all();
		}
		break;

	case SIGHUP:
		warning(0, "SIGHUP received, catching and re-opening logs");
		log_reopen();
		alog_reopen();
		break;

		/*
		 * It would be more proper to use SIGUSR1 for this, but on some
		 * platforms that's reserved by the pthread support.
		 */
	case SIGQUIT:
		warning(0, "SIGQUIT received, reporting memory usage.");
		gw_check_leaks();
		break;
	}
}

static void setup_signal_handlers(void) {
	struct sigaction act;

	act.sa_handler = signal_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGQUIT, &act, NULL);
	sigaction(SIGHUP, &act, NULL);
	sigaction(SIGPIPE, &act, NULL);
	sigaction(SIGTERM, &act, NULL);
}

static void gw_smpp_enter(Cfg *cfg) {
}

static void gw_smpp_leave() {
}

static void init_smpp_server_box(Cfg *cfg) {
	CfgGroup *cfg_group;
	Octstr *log_file;

	long log_level;
	/* some default values */
	smppbox_port = 13005;
	log_file = NULL;
	log_level = 0;

	MYSQL_RES *result = NULL;
	MYSQL_ROW row = NULL;


	debug("smppServer", 0, "********** SMPP Server Box Configuration Initialization **********");

	/* initialize low level PDUs */
	if (smpp_pdu_init(cfg) == -1)
		panic(0, "Connot start with PDU init failed.");

	/*
	 * first we take the port number in bearerbox and other values from the
	 * smppServer group in configuration file
	 */

	cfg_group = cfg_get_single_group(cfg, octstr_imm("smppServer"));
	if (cfg_group == NULL)
		panic(0, "No 'smppServer' group in configuration");

	smppbox_id = cfg_get(cfg_group, octstr_imm("smppServer-id"));
	integratorId = cfg_get(cfg_group, octstr_imm("integrator-id"));
	integratorQueueId = cfg_get(cfg_group, octstr_imm("integrator-queue-id"));
	our_system_id = cfg_get(cfg_group, octstr_imm("our-system-id"));
	if (our_system_id == NULL) {
		panic(0, "our-system-id is not set.");
	}

	/* setup logfile stuff */
	log_file = cfg_get(cfg_group, octstr_imm("log-file"));

	cfg_get_integer(&log_level, cfg_group, octstr_imm("log-level"));

	if (cfg_get_integer(&smppbox_port, cfg_group, octstr_imm("smppServer-port")) == -1)
		smppbox_port = 2345;

	if (log_file != NULL) {
		info(0, "Starting to log to file %s level %ld", octstr_get_cstr(log_file), log_level);
		log_open(octstr_get_cstr(log_file), log_level, GW_NON_EXCL);

	}

	if (cfg_get_integer(&smpp_timeout, cfg_group, octstr_imm("timeout")) == -1)
		smpp_timeout = TIMEOUT_SECONDS;
	if (cfg_get_integer(&smpp_source_addr_ton, cfg_group, octstr_imm("source-addr-ton")) == -1)
		smpp_source_addr_ton = -1;
	if (cfg_get_integer(&smpp_source_addr_npi, cfg_group, octstr_imm("source-addr-npi")) == -1)
		smpp_source_addr_npi = -1;
	if (cfg_get_bool(&smpp_autodetect_addr, cfg_group, octstr_imm("source-addr-auto")) == -1)
		smpp_autodetect_addr = 0;
	if (cfg_get_integer(&smpp_dest_addr_ton, cfg_group, octstr_imm("dest-addr-ton")) == -1)
		smpp_dest_addr_ton = -1;
	if (cfg_get_integer(&smpp_dest_addr_npi, cfg_group, octstr_imm("dest-addr-npi")) == -1)
		smpp_dest_addr_npi = -1;
	if (cfg_get_bool(&receiver_mode, cfg_group, octstr_imm("receiver-mode")) == -1
			& cfg_get_bool(&transmitter_mode, cfg_group, octstr_imm("transmitter-mode")) == -1) {
		panic(0, "Connection should be receiver mode or transmitter mode");
	} else if (receiver_mode == 1 && transmitter_mode == 1) {
		panic(0, "Connection should be receiver mode or transmitter mode");
	}

	debug("smppServer", 0, "==========Configuration Parameters============");
	debug("smppServer", 0, "===> smppServer-id:          %s ", octstr_get_cstr(smppbox_id));
	debug("smppServer", 0, "===> integrator-id:          %s", octstr_get_cstr(integratorId));
	debug("smppServer", 0, "===> integrator-queue-id:    %s", octstr_get_cstr(integratorQueueId));
	debug("smppServer", 0, "===> smppServer-port:        %ld", smppbox_port);
	debug("smppServer", 0, "===> our-system-id:          %s ", octstr_get_cstr(our_system_id));
	debug("smppclient", 0, "===> mode:                   %s ", (transmitter_mode ? "TX" : "RX"));
	debug("smppServer", 0, "===> timeout:                %ld ", smpp_timeout);
	debug("smppServer", 0, "===> log-file:               %s ", octstr_get_cstr(log_file));
	debug("smppServer", 0, "===> log-level:              %ld", log_level);
	debug("smppServer", 0, "===> source_addr_ton:        %ld", smpp_source_addr_ton);
	debug("smppServer", 0, "===> source_addr_npi:        %ld", smpp_source_addr_npi);
	debug("smppServer", 0, "===> dest_addr_ton:          %ld", smpp_dest_addr_ton);
	debug("smppServer", 0, "===> dest_addr_npi:          %ld", smpp_dest_addr_npi);
	debug("smppServer", 0, "==============================================");

	result = mysql_select(octstr_format(SQL_SELECT_CARRIER_ROUTE));
	numberCarrierRoutes = mysql_num_rows(result);
	carrierRoutes=gw_malloc(sizeof(CarrierRoute)*numberCarrierRoutes);
	int i=0;
	while ((row = mysql_fetch_row(result))) {
		CarrierRoute carrierRoute;
		carrierRoute.id=octstr_imm(row[0]);
		carrierRoute.name=octstr_imm(row[1]);
		carrierRoute.preffix=octstr_imm(row[2]);
		carrierRoutes[i]=carrierRoute;
		i++;
	}
	mysql_free_result(result);

	int j;
	debug("smppServer", 0, "==========Preffix Mapping============");
	for(j=0;j<numberCarrierRoutes;j++){
		debug("smppClient",0,"[Id:%s] [name:%s]  [preffix:%s]",octstr_get_cstr(carrierRoutes[j].id),octstr_get_cstr(carrierRoutes[j].name),octstr_get_cstr(carrierRoutes[j].preffix));
	}
	debug("smppServer", 0, "=====================================");


	octstr_destroy(log_file);
	gw_smpp_enter(cfg);
	smppbox_status = SMPP_RUNNING;
	debug("smppServer", 0, "smpp_status: %d ", smppbox_status);
	debug("smppServer", 0, "********** SMPP Server Box Configuration End **********");
}

static int check_args(int i, int argc, char **argv) {
	if (strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--tryhttp") == 0) {
		//only_try_http = 1;
	} else
		return -1;

	return 0;
}

/*
 * Adding hooks to kannel check config
 *
 * Martin Conte.
 */

static int smppbox_is_allowed_in_group(Octstr *group, Octstr *variable) {
	Octstr *groupstr;

	groupstr = octstr_imm("group");

#define OCTSTR(name) \
        if (octstr_compare(octstr_imm(#name), variable) == 0) \
        return 1;
#define SINGLE_GROUP(name, fields) \
        if (octstr_compare(octstr_imm(#name), group) == 0) { \
        if (octstr_compare(groupstr, variable) == 0) \
        return 1; \
        fields \
        return 0; \
    }
#define MULTI_GROUP(name, fields) \
        if (octstr_compare(octstr_imm(#name), group) == 0) { \
        if (octstr_compare(groupstr, variable) == 0) \
        return 1; \
        fields \
        return 0; \
    }
#include "smppServer-cfg.def"

	return 0;
}

#undef OCTSTR
#undef SINGLE_GROUP
#undef MULTI_GROUP

static int smppbox_is_single_group(Octstr *query) {
#define OCTSTR(name)
#define SINGLE_GROUP(name, fields) \
        if (octstr_compare(octstr_imm(#name), query) == 0) \
        return 1;
#define MULTI_GROUP(name, fields) \
        if (octstr_compare(octstr_imm(#name), query) == 0) \
        return 0;
#include "smppServer-cfg.def"
	return 0;
}

static void smpp_server_box_shutdown(void) {
	octstr_destroy(our_system_id);
	our_system_id = NULL;
	octstr_destroy(smppbox_id);
	smppbox_id = NULL;
	integratorId = NULL;
	integratorQueueId = NULL;
	smpp_pdu_shutdown();
}

int main(int argc, char **argv) {
	int cf_index;
	Octstr *filename, *version;

	gwlib_init();
	list_dict = dict_create(32, msg_list_destroy_item);

	cf_index = get_and_set_debugs(argc, argv, check_args);
	setup_signal_handlers();

	if (argv[cf_index] == NULL)
		filename = octstr_create("smppServer.conf");
	else
		filename = octstr_create(argv[cf_index]);

	cfg = cfg_create(filename);

	/* Adding cfg-checks to core */
	cfg_add_hooks(smppbox_is_allowed_in_group, smppbox_is_single_group);

	if (cfg_read(cfg) == -1)
		panic(0, "Couldn't read configuration from `%s'.", octstr_get_cstr(filename));

	octstr_destroy(filename);

	version = octstr_format("smppServer version %s gwlib", GW_VERSION);
	report_versions(octstr_get_cstr(version));
	octstr_destroy(version);

	struct server_type *res = NULL;
	res = sqlbox_init_mysql(cfg);
	sqlbox_configure_mysql(cfg);

	init_smpp_server_box(cfg);
	smpp_server_box_run((void *) smppbox_port);

	gwthread_join_every(sql_to_smpp);
	gwthread_join_every(smpp_to_sql);
	smpp_server_box_shutdown();

	dict_destroy(list_dict);
	list_dict = NULL;

	cfg_destroy(cfg);

	if (restart_smppbox) {
		gwthread_sleep(1.0);
	}

	gw_smpp_leave();
	gwlib_shutdown();

	if (restart_smppbox)
		execvp(argv[0], argv);
	return 0;
}
