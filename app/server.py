#!/usr/bin/env python3
"""Durable Alertmanager -> ManageEngine Applications Manager slot bridge (stdlib only)."""
import base64
import hashlib
import hmac
import json
import logging
import os
import re
import signal
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

logging.basicConfig(level=os.getenv('LOG_LEVEL', 'INFO'), format='%(asctime)s %(levelname)s %(message)s')
log = logging.getLogger('me-alert-sync')
HOST = os.getenv('LISTEN_HOST', '0.0.0.0')
PORT = int(os.getenv('LISTEN_PORT', '18082'))
USER = os.getenv('WEBHOOK_USER', '')
PASSWORD_FILE = os.getenv('WEBHOOK_PASSWORD_FILE', '/run/secrets/webhook_password')
ME_URL = os.getenv('ME_URL', '').rstrip('/')
RESOURCE = os.getenv('ME_RESOURCE_ID', '')
SLOTS = [x.strip() for x in os.getenv('ME_SLOT_ATTRIBUTE_IDS', '').split(',') if x.strip()]
DB_PATH = os.getenv('DB_PATH', '/data/alerts.sqlite3')
IDENTITY = os.getenv('IDENTITY_MODE', 'instance')
VERIFY = os.getenv('ME_VERIFY_TLS', 'true').lower() in ('1','true','yes')
TIMEOUT = float(os.getenv('ME_TIMEOUT', '10'))
RETRY_SECONDS = int(os.getenv('RETRY_SECONDS', '15'))
MAX_BODY = int(os.getenv('MAX_BODY_BYTES', '2097152'))
API_KEY_FILE = os.getenv('ME_API_KEY_FILE', '/run/secrets/me_api_key')
FEED_TOKEN_FILE = os.getenv('ME_FEED_TOKEN_FILE', '/run/secrets/feed_token')
INTEGRATION_MODE = os.getenv('APPMANAGER_INTEGRATION_MODE', 'dynamic_rest_monitor')
FEED_BASE_URL = os.getenv('ME_FEED_BASE_URL', 'http://117.5.151.176:18082').rstrip('/')
RESOLVED_RETENTION = int(os.getenv('RESOLVED_MONITOR_RETENTION_HOURS', '24')) * 3600
SYNC_INTERVAL = int(os.getenv('SYNC_INTERVAL', '30'))
DB_LOCK = threading.RLock()
WAKE = threading.Event()
STOP = threading.Event()


def valid_slot(slot):
    """Accept a legacy attribute ID or an explicit resourceid:attributeid slot."""
    parts = slot.split(':')
    return (len(parts) == 1 and parts[0].isdecimal()) or (
        len(parts) == 2 and parts[0].isdecimal() and parts[1].isdecimal()
    )


def slot_target(slot):
    """Return the AppManager resource and attribute addressed by a slot."""
    if ':' in slot:
        return tuple(slot.split(':', 1))
    return RESOURCE, slot


def secret(path, fallback=''):
    try:
        return Path(path).read_text().strip()
    except OSError:
        return os.getenv(fallback, '') if fallback else ''


def connect():
    db = sqlite3.connect(DB_PATH, timeout=30, check_same_thread=False)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=30000')
    db.execute('PRAGMA journal_mode=WAL')
    db.execute('PRAGMA synchronous=FULL')
    return db


def init():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    with connect() as db:
        db.executescript('''
CREATE TABLE IF NOT EXISTS alerts (
 key TEXT PRIMARY KEY, status TEXT NOT NULL, payload TEXT NOT NULL,
 slot TEXT, delivered_status TEXT, delivered_message TEXT,
 next_attempt REAL NOT NULL DEFAULT 0, attempts INTEGER NOT NULL DEFAULT 0,
 error TEXT NOT NULL DEFAULT '', updated REAL NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS slot_unique ON alerts(slot) WHERE slot IS NOT NULL;
CREATE TABLE IF NOT EXISTS counters (name TEXT PRIMARY KEY, value INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS alert_monitor_mappings (
 fingerprint TEXT PRIMARY KEY, monitor_name TEXT NOT NULL UNIQUE,
 appmanager_resourceid TEXT, alertname TEXT, application TEXT, instance TEXT,
 summary TEXT, alert_state TEXT NOT NULL, starts_at TEXT, ends_at TEXT,
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL, resolved_at TEXT,
 cleanup_after REAL, last_error TEXT NOT NULL DEFAULT ''
);
''')


def stable_key(alert):
    if alert.get('fingerprint'):
        return str(alert['fingerprint'])
    labels = alert['labels']
    if IDENTITY == 'rule':
        return str(labels.get('me_monitor') or labels.get('alertname') or 'unknown')
    # Canonical labels avoid Python salted hash and fingerprint differences across AM instances.
    return hashlib.sha256(json.dumps(labels, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()


def make_message(alert):
    a = alert.get('annotations') or {}
    labels = alert.get('labels') or {}
    # Keep the fields visible in AppManager's single alarm-message column.
    # The labels remain in the durable payload for correlation and auditing.
    summary = a.get('summary') or a.get('message') or a.get('description') or 'Alert'
    name = labels.get('alertname') or labels.get('alert_name') or 'Alert'
    application = labels.get('application') or labels.get('app') or ''
    instance = labels.get('instance') or ''
    fields = [f'Thong diep canh bao = {summary}', f'Ten = {name}']
    if application:
        fields.append(f'Ten may chu = {application}')
    if instance:
        fields.append(f'Dia chi IP = {instance}')
    return '; '.join(str(x) for x in fields)[:900]


def normalize(alert):
    if not isinstance(alert, dict) or not isinstance(alert.get('labels'), dict):
        raise ValueError('Each alert must contain labels object')
    status = alert.get('status')
    if status not in ('firing', 'resolved'):
        raise ValueError('Alert status must be firing or resolved')
    labels = alert['labels']
    severity = str(labels.get('severity', 'critical')).lower()
    sev = 4 if severity in ('warning','warn') else 1
    a = alert.get('annotations') or {}
    summary = a.get('summary') or a.get('message') or a.get('description') or 'Alert'
    return stable_key(alert), status, json.dumps({'message': make_message(alert), 'summary': summary, 'severity': sev, 'labels': labels,
        'fingerprint': alert.get('fingerprint',''), 'startsAt': alert.get('startsAt'), 'endsAt': alert.get('endsAt')}, ensure_ascii=False)


def safe_name(value, fallback='unknown', limit=48):
    value = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(value or fallback)).strip('_') or fallback
    return value[:limit]


def monitor_name(key, data):
    labels = data.get('labels', {})
    return 'AM_%s_%s_%s_%s' % (safe_name(labels.get('alertname')), safe_name(labels.get('application') or labels.get('app')), safe_name(labels.get('instance')), safe_name(key[-8:], 'unknown', 8))


class AppManagerClient:
    def __init__(self):
        self.key = secret(API_KEY_FILE, 'ME_API_KEY')
        self.ctx = ssl.create_default_context() if VERIFY else ssl._create_unverified_context()

    def _call(self, path, params):
        params = dict(params, apikey=self.key)
        req = urllib.request.Request(f'{ME_URL}/AppManager/xml/{path}', data=urllib.parse.urlencode(params).encode(), method='POST', headers={'Content-Type':'application/x-www-form-urlencoded'})
        with urllib.request.urlopen(req, context=self.ctx, timeout=TIMEOUT) as r: body = r.read(128*1024).decode('utf-8','replace')
        root = ET.fromstring(body); response = root.find('.//response'); code = response.attrib.get('response-code') if response is not None else None
        if str(code) not in ('4000','200'):
            msg = response.findtext('message','') if response is not None else ''
            raise RuntimeError(f'AppManager {path} response-code={code} message={msg[:180]}')
        return response.attrib.get('resourceid','') if response is not None else ''

    def create_rest_monitor(self, name, feed_url):
        token = secret(FEED_TOKEN_FILE, 'ME_FEED_TOKEN')
        # AppManager 18.2.600 names this field customHeaders and uses _sep_ between header name/value.
        return self._call('AddMonitor', {'type':'RESTAPIMonitor','displayname':name,'API':feed_url,'Timeout':'10','Method':'GET','RespType':'JSON','ContentCheck':'false','customHeaders':('Authorization_sep_Bearer '+token) if token else '','haid':RESOURCE})

    def delete_monitor(self, resourceid):
        self._call('DeleteMonitor', {'resourceid':resourceid})


ME_CLIENT = AppManagerClient()


def inc(db, name, amount=1):
    db.execute('INSERT INTO counters(name,value) VALUES (?,?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value', (name, amount))


def ingest(payload):
    if payload.get('version') != '4' or not isinstance(payload.get('alerts'), list):
        raise ValueError('Expect Alertmanager webhook version 4 and alerts array')
    if payload.get('truncatedAlerts', 0):
        raise ValueError('truncatedAlerts > 0; configure max_alerts: 0')
    normalized = [normalize(x) for x in payload['alerts']]
    now = time.time()
    with DB_LOCK, connect() as db:
        db.execute('BEGIN IMMEDIATE')
        for key, status, data in normalized:
            old = db.execute('SELECT status, delivered_status, payload FROM alerts WHERE key=?', (key,)).fetchone()
            if old:
                if old['status'] == status and old['payload'] == data:
                    continue
                db.execute('UPDATE alerts SET status=?, payload=?, next_attempt=0, updated=? WHERE key=?', (status,data,now,key))
            elif status == 'firing':
                db.execute('INSERT INTO alerts(key,status,payload,updated) VALUES (?,?,?,?)', (key,status,data,now))
            inc(db, 'received')
    WAKE.set()
    return len(normalized)


def generate_alert(slot, severity, message):
    key = secret(API_KEY_FILE, 'ME_API_KEY')
    if not key:
        return False, 'missing ME API key'
    resource, attribute = slot_target(slot)
    params = urllib.parse.urlencode({
        'apikey': key, 'resourceid': resource, 'attributeid': attribute,
        'entity': f'{resource}_{attribute}', 'severity': str(severity),
        'alarmMessage': message,
    })
    # XML is the documented Applications Manager endpoint and is available
    # consistently on installations where the JSON alias only acknowledges
    # the request without surfacing the attribute alarm in the UI.
    url = f'{ME_URL}/AppManager/xml/generateAlert?{params}'
    ctx = ssl.create_default_context() if VERIFY else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(url, context=ctx, timeout=TIMEOUT) as response:
            body = response.read(1024 * 128).decode('utf-8', 'replace')
        code = None
        try:
            parsed = json.loads(body)
            code = parsed.get('response-code')
            if code is None and isinstance(parsed.get('response'), dict):
                code = parsed['response'].get('response-code')
        except json.JSONDecodeError:
            root = ET.fromstring(body)
            response = root.find('.//response')
            code = response.attrib.get('response-code') if response is not None else None
        ok = str(code) == '4000'
        return ok, 'ME response-code=' + str(code) + ('' if ok else ' body=' + body[:300])
    except (urllib.error.URLError, TimeoutError, ValueError, OSError) as e:
        return False, f'{type(e).__name__}: {e}'


def dynamic_feed(key):
    with DB_LOCK, connect() as db:
        row = db.execute('SELECT status,payload FROM alerts WHERE key=?', (key,)).fetchone()
    if not row:
        return None
    data = json.loads(row['payload']); labels = data.get('labels', {})
    return {'status': 'CRITICAL' if row['status']=='firing' else 'OK', 'fingerprint': key,
            'alertname': labels.get('alertname',''), 'application': labels.get('application') or labels.get('app',''),
            'instance': labels.get('instance',''), 'summary': data.get('summary') or data.get('message',''),
            'startsAt': data.get('startsAt'), 'endsAt': data.get('endsAt')}


def process_dynamic_one():
    now=time.time()
    with DB_LOCK, connect() as db:
        rows=db.execute("SELECT * FROM alerts WHERE next_attempt<=? ORDER BY updated ASC",(now,)).fetchall()
    for row in rows:
        key,status=row['key'],row['status']; data=json.loads(row['payload'])
        if status == 'resolved' and row['delivered_status'] == 'resolved':
            continue
        with DB_LOCK, connect() as db:
            mapping=db.execute('SELECT * FROM alert_monitor_mappings WHERE fingerprint=?',(key,)).fetchone()
        if status=='firing' and not mapping:
            name=monitor_name(key,data); feed=f'{FEED_BASE_URL}/appmanager-feed/{urllib.parse.quote(key,safe="")}?bootstrap=1'
            try:
                rid=ME_CLIENT.create_rest_monitor(name,feed)
                ts=time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()); labels=data.get('labels',{}); app=labels.get('application') or labels.get('app','')
                with DB_LOCK, connect() as db:
                    db.execute('INSERT OR IGNORE INTO alert_monitor_mappings (fingerprint,monitor_name,appmanager_resourceid,alertname,application,instance,summary,alert_state,starts_at,ends_at,created_at,updated_at,resolved_at,cleanup_after) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(key,name,rid,labels.get('alertname',''),app,labels.get('instance',''),data.get('summary') or data.get('message',''),status,data.get('startsAt'),data.get('endsAt'),ts,ts,None,None))
                    db.execute('UPDATE alerts SET delivered_status=?,delivered_message=?,attempts=0,error=?,next_attempt=?,updated=? WHERE key=?',(status,data.get('message',''),'',now+SYNC_INTERVAL,now,key)); inc(db, 'monitors_created')
                log.info('MONITOR_CREATED fingerprint=%s resourceid=%s name=%s',key,rid,name); return True
            except Exception as exc:
                attempts=row['attempts']+1; delay=min(300,RETRY_SECONDS*(2**min(attempts-1,5)))
                with DB_LOCK, connect() as db:
                    db.execute('UPDATE alerts SET attempts=?,error=?,next_attempt=? WHERE key=?',(attempts,str(exc)[:300],now+delay,key)); inc(db,'appmanager_errors')
                log.warning('RETRY fingerprint=%s reason=%s',key,str(exc)[:300]); return True
        if status=='firing' and mapping:
            labels=data.get('labels',{}); app=labels.get('application') or labels.get('app','')
            with DB_LOCK, connect() as db:
                db.execute('UPDATE alert_monitor_mappings SET alertname=?,application=?,instance=?,summary=?,alert_state=?,starts_at=?,ends_at=?,updated_at=?,resolved_at=NULL,cleanup_after=NULL,last_error=? WHERE fingerprint=?',(labels.get('alertname',''),app,labels.get('instance',''),data.get('summary') or data.get('message',''),'firing',data.get('startsAt'),data.get('endsAt'),time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'',key))
                db.execute('UPDATE alerts SET delivered_status=?,delivered_message=?,attempts=0,error=?,next_attempt=?,updated=? WHERE key=?',(status,data.get('message',''),'',now+SYNC_INTERVAL,now,key))
            return True
        if status=='resolved' and mapping:
            with DB_LOCK, connect() as db:
                db.execute('UPDATE alert_monitor_mappings SET alert_state=?,resolved_at=?,cleanup_after=?,updated_at=?,last_error=? WHERE fingerprint=?',('resolved',time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),now+RESOLVED_RETENTION,time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'',key)); db.execute('UPDATE alerts SET delivered_status=?,delivered_message=?,attempts=0,error=?,next_attempt=?,updated=? WHERE key=?',(status,data.get('message',''),'',now+SYNC_INTERVAL,now,key)); inc(db,'monitors_resolved')
            log.info('MONITOR_RESOLVED fingerprint=%s resourceid=%s',key,mapping['appmanager_resourceid']); return True
    return False


def cleanup_dynamic():
    if INTEGRATION_MODE != 'dynamic_rest_monitor': return
    with DB_LOCK, connect() as db:
        rows=db.execute('SELECT * FROM alert_monitor_mappings WHERE cleanup_after IS NOT NULL AND cleanup_after<=?',(time.time(),)).fetchall()
        for row in rows:
            try: ME_CLIENT.delete_monitor(row['appmanager_resourceid']); db.execute('DELETE FROM alert_monitor_mappings WHERE fingerprint=?',(row['fingerprint'],)); db.execute('DELETE FROM alerts WHERE key=?',(row['fingerprint'],)); inc(db,'monitors_deleted'); db.commit(); log.info('MONITOR_DELETED fingerprint=%s resourceid=%s',row['fingerprint'],row['appmanager_resourceid'])
            except Exception as exc: db.execute('UPDATE alert_monitor_mappings SET last_error=?,cleanup_after=? WHERE fingerprint=?',(str(exc)[:300],time.time()+RETRY_SECONDS,row['fingerprint'])); db.commit()


def process_one():
    if INTEGRATION_MODE == 'dynamic_rest_monitor':
        return process_dynamic_one()
    with DB_LOCK, connect() as db:
        db.execute('BEGIN IMMEDIATE')
        now = time.time()
        rows = db.execute('SELECT * FROM alerts WHERE next_attempt<=? ORDER BY updated ASC', (now,)).fetchall()
        for row in rows:
            key, status, slot = row['key'], row['status'], row['slot']
            if status == 'resolved' and slot is None:
                db.execute('DELETE FROM alerts WHERE key=?', (key,))
                continue
            data = json.loads(row['payload'])
            msg = data['message']
            if status == 'resolved':
                sev, msg = 5, f'OK - {msg}'[:900]
            else:
                sev = data['severity']
                if slot is None:
                    used = {r[0] for r in db.execute('SELECT slot FROM alerts WHERE slot IS NOT NULL')}
                    slot = next((s for s in SLOTS if s not in used), None)
                    if not slot:
                        # Queue until capacity free, never pretend successfully forwarded.
                        db.execute('UPDATE alerts SET next_attempt=? WHERE key=?', (now+RETRY_SECONDS,key))
                        continue
                    # Reserve slot DURABLY before talking to ME.
                    db.execute('UPDATE alerts SET slot=? WHERE key=?', (slot,key))
                    db.commit()
                    db.execute('BEGIN IMMEDIATE')
                if row['delivered_status'] == status and row['delivered_message'] == msg:
                    continue
            ok, result = generate_alert(slot, sev, msg)
            if ok:
                if status == 'resolved':
                    db.execute('DELETE FROM alerts WHERE key=?', (key,))
                else:
                    db.execute('UPDATE alerts SET delivered_status=?, delivered_message=?, attempts=0,error="",next_attempt=?,updated=? WHERE key=?',
                               (status,msg,now+SYNC_INTERVAL,now,key))
                inc(db, 'delivered')
                log.info('DELIVERED key=%s slot=%s state=%s', key,slot,status)
            else:
                attempts = row['attempts'] + 1
                delay = min(300, RETRY_SECONDS * (2 ** min(attempts - 1, 5)))
                db.execute('UPDATE alerts SET attempts=?,error=?,next_attempt=? WHERE key=?', (attempts,result[:300],now+delay,key))
                inc(db, 'errors')
                log.warning('RETRY key=%s slot=%s state=%s reason=%s', key,slot,status,result)
            return True
    return False


def worker():
    while not STOP.is_set():
        try:
            cleanup_dynamic()
            if process_one():
                continue
        except Exception:
            log.exception('Worker error')
        WAKE.wait(timeout=2)
        WAKE.clear()


def snapshot():
    with DB_LOCK, connect() as db:
        rows = [dict(r) for r in db.execute('SELECT key,status,slot,delivered_status,attempts,error,updated FROM alerts ORDER BY updated DESC')]
        mappings = [dict(r) for r in db.execute('SELECT fingerprint,monitor_name,appmanager_resourceid,alertname,application,instance,summary,alert_state,updated_at,last_error FROM alert_monitor_mappings ORDER BY updated_at DESC')]
        counters = dict(db.execute('SELECT name,value FROM counters').fetchall())
    used = {r['slot'] for r in rows if r['slot']}
    return {'mode':INTEGRATION_MODE,'slots_total':len(SLOTS),'slots_used':len(used),'slots_free':len(SLOTS)-len(used),
            'queued':sum(r['slot'] is None for r in rows), 'pending':sum(r['status']!=r['delivered_status'] for r in rows),
            'alerts': rows,'mappings':mappings,'counters':counters,'identity_mode':IDENTITY,'resourceid':RESOURCE}


def appmanager_feed():
    """Read-only JSON feed for an AppManager RESTAPIMonitor."""
    with DB_LOCK, connect() as db:
        rows = db.execute('SELECT key,status,payload,delivered_status,updated FROM alerts ORDER BY updated DESC').fetchall()
    alerts = []
    for row in rows:
        data = json.loads(row['payload'])
        alerts.append({'key': row['key'], 'status': row['status'],
                       'delivered_status': row['delivered_status'],
                       'message': data.get('message',''),
                       'alertname': data.get('labels',{}).get('alertname',''),
                       'application': data.get('labels',{}).get('application') or data.get('labels',{}).get('app',''),
                       'instance': data.get('labels',{}).get('instance',''),
                       'updated': row['updated']})
    return {'alert_count': len(alerts), 'active_count': sum(x['status']=='firing' for x in alerts), 'alerts': alerts}


class Handler(BaseHTTPRequestHandler):
    server_version = 'me-alert-sync/2.0'
    def log_message(self, fmt, *args):
        log.info('%s %s', self.address_string(), fmt % args)

    def send_json(self, code, value):
        body = json.dumps(value,ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header('Content-Type','application/json; charset=utf-8')
        self.send_header('Content-Length',str(len(body)))
        self.send_header('Cache-Control','no-store')
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        pwd = secret(PASSWORD_FILE, 'WEBHOOK_PASSWORD')
        if not USER or not pwd:
            return False
        h = self.headers.get('Authorization','')
        if not h.startswith('Basic '):
            return False
        try:
            decoded=base64.b64decode(h[6:],validate=True).decode()
        except (ValueError, UnicodeError):
            return False
        return hmac.compare_digest(decoded,f'{USER}:{pwd}')

    def do_POST(self):
        if self.path != '/alertmanager-webhook':
            return self.send_json(404,{'error':'not found'})
        if not self.authorized():
            return self.send_json(401,{'error':'unauthorized'})
        try:
            length = int(self.headers.get('Content-Length','0'))
            if not 0 < length <= MAX_BODY:
                return self.send_json(413,{'error':'body too large or empty'})
            payload = json.loads(self.rfile.read(length))
            count = ingest(payload)
            return self.send_json(202,{'accepted':count,'durable':True})
        except (ValueError,TypeError,sqlite3.Error) as exc:
            log.warning('Webhook rejected: %s',exc)
            return self.send_json(400 if not isinstance(exc,sqlite3.Error) else 503,{'error':str(exc)[:200]})

    def do_GET(self):
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == '/appmanager-feed' or parsed.path.startswith('/appmanager-feed/'):
            feed_token = secret(FEED_TOKEN_FILE, 'ME_FEED_TOKEN')
            auth = self.headers.get('Authorization','')
            bearer = auth[7:] if auth.startswith('Bearer ') else ''
            legacy = urllib.parse.parse_qs(parsed.query).get('token', [''])[0]
            if not feed_token or not (hmac.compare_digest(bearer, feed_token) or (parsed.path == '/appmanager-feed' and hmac.compare_digest(legacy, feed_token))):
                return self.send_json(401, {'error':'unauthorized'})
            try:
                if parsed.path != '/appmanager-feed':
                    key = urllib.parse.unquote(parsed.path.rsplit('/',1)[-1])
                    value = dynamic_feed(key)
                    if value is None: return self.send_json(404, {'error':'fingerprint not found'})
                    # A firing alert is deliberately non-2xx so RESTAPIMonitor raises an availability alarm.
                    if value['status'] == 'CRITICAL' and urllib.parse.parse_qs(parsed.query).get('bootstrap') == ['1']:
                        with DB_LOCK, connect() as db:
                            if db.execute('SELECT 1 FROM alert_monitor_mappings WHERE fingerprint=?',(key,)).fetchone() is None:
                                return self.send_json(200, value)
                    return self.send_json(500 if value['status']=='CRITICAL' else 200, value)
                return self.send_json(200, appmanager_feed())
            except sqlite3.Error:
                return self.send_json(503, {'error':'database unavailable'})
        if self.path == '/health':
            return self.send_json(200,{'status':'alive'})
        if self.path == '/ready':
            try:
                with connect() as db: db.execute('SELECT 1').fetchone()
                return self.send_json(200,{'status':'ready'})
            except sqlite3.Error:
                return self.send_json(503,{'status':'database unavailable'})
        if self.path == '/status':
            if not self.authorized():
                return self.send_json(401,{'error':'unauthorized'})
            return self.send_json(200,snapshot())
        if parsed.path == '/metrics':
            s=snapshot(); c=s.get('counters',{})
            body='\n'.join([f'me_alert_{k} {v}' for k,v in c.items()] + [f'me_alert_queue_depth {len(s["alerts"])}',f'me_alert_mapping_count {len(s["mappings"])}'])+'\n'
            raw=body.encode(); self.send_response(200); self.send_header('Content-Type','text/plain; version=0.0.4'); self.send_header('Content-Length',str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        if parsed.path == '/api/v1/alert-mappings' or parsed.path.startswith('/api/v1/alert-mappings/'):
            if not self.authorized(): return self.send_json(401,{'error':'unauthorized'})
            snap=snapshot()
            if parsed.path != '/api/v1/alert-mappings':
                key=urllib.parse.unquote(parsed.path.rsplit('/',1)[-1]); item=next((x for x in snap['mappings'] if x['fingerprint']==key),None)
                return self.send_json(200,item) if item else self.send_json(404,{'error':'fingerprint not found'})
            return self.send_json(200,{'mappings':snap['mappings']})
        return self.send_json(404,{'error':'not found'})


def main():
    if not ME_URL.startswith(('https://','http://')) or not RESOURCE.isdecimal() or IDENTITY not in ('instance','rule') or (INTEGRATION_MODE != 'dynamic_rest_monitor' and (not SLOTS or any(not valid_slot(x) for x in SLOTS) or len(SLOTS)!=len(set(SLOTS)))):
        raise SystemExit('Invalid ME_URL / ME_RESOURCE_ID / ME_SLOT_ATTRIBUTE_IDS / IDENTITY_MODE')
    if not USER or not secret(PASSWORD_FILE,'WEBHOOK_PASSWORD') or not secret(API_KEY_FILE,'ME_API_KEY'):
        raise SystemExit('Webhook Basic Auth and ME API key are required')
    init()
    threading.Thread(target=worker,daemon=True).start()
    server = ThreadingHTTPServer((HOST,PORT),Handler)
    def stop(*_):
        STOP.set(); WAKE.set()
        threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,stop)
    signal.signal(signal.SIGINT,stop)
    log.info('listening port=%s slots=%d integration_mode=%s identity=%s',PORT,len(SLOTS),INTEGRATION_MODE,IDENTITY)
    server.serve_forever()
    server.server_close()

if __name__ == '__main__': main()
