import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch

os.environ.setdefault('ME_URL','https://example.local:8443')
os.environ.setdefault('ME_RESOURCE_ID','10000140')
os.environ.setdefault('ME_SLOT_ATTRIBUTE_IDS','400,401')
root = os.path.dirname(os.path.dirname(__file__))
spec=importlib.util.spec_from_file_location('server',root+'/app/server.py')
s=importlib.util.module_from_spec(spec)
spec.loader.exec_module(s)

class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        s.DB_PATH=self.tmp.name+'/state.sqlite3'
        s.init()
        s.INTEGRATION_MODE='legacy_slots'
        self.alert={'status':'firing','labels':{'alertname':'HighCPU','instance':'a','severity':'warning'},'annotations':{'summary':'hello'}}
    def tearDown(self): self.tmp.cleanup()
    def test_durable_state_retry_clear(self):
        s.ingest({'version':'4','alerts':[self.alert]})
        with patch.object(s,'generate_alert',return_value=(True,'ok')) as me:
            self.assertTrue(s.process_one())
            self.assertEqual(me.call_args.args[1],4)
        self.assertEqual(s.snapshot()['slots_used'],1)
        s.ingest({'version':'4','alerts':[{**self.alert,'status':'resolved'}]})
        with patch.object(s,'generate_alert',side_effect=[(False,'network down'),(True,'ok')]) as me:
            s.process_one()
            self.assertEqual(s.snapshot()['slots_used'],1)
            with s.connect() as db:
                db.execute('UPDATE alerts SET next_attempt=0')
            s.process_one()
            self.assertEqual(me.call_args.args[1],5)
        self.assertEqual(s.snapshot()['slots_used'],0)
    def test_overflow_is_queued(self):
        alerts=[{**self.alert,'labels':{**self.alert['labels'],'instance':str(n)}} for n in range(3)]
        s.ingest({'version':'4','alerts':alerts})
        with patch.object(s,'generate_alert',return_value=(True,'ok')):
            for _ in range(3): s.process_one()
        self.assertEqual(s.snapshot()['slots_used'],2)
        self.assertEqual(s.snapshot()['queued'],1)
    def test_reject_truncated(self):
        with self.assertRaises(ValueError): s.ingest({'version':'4','alerts':[],'truncatedAlerts':3})
    def test_identity_stable(self):
        self.assertEqual(s.stable_key(self.alert),s.stable_key(self.alert))
    def test_explicit_resource_attribute_slot(self):
        self.assertEqual(s.slot_target('10000380:402'),('10000380','402'))
        self.assertTrue(s.valid_slot('10000380:402'))
        self.assertTrue(s.valid_slot('402'))
        self.assertFalse(s.valid_slot('10000380:not-an-attribute'))

    def test_dynamic_fingerprint_idempotent_and_resolved(self):
        s.INTEGRATION_MODE='dynamic_rest_monitor'
        alert={**self.alert,'fingerprint':'fp-one','labels':{**self.alert['labels'],'application':'app1','instance':'10.0.0.1:9100'}}
        s.ingest({'version':'4','alerts':[alert]})
        with patch.object(s.ME_CLIENT,'create_rest_monitor',return_value='9001') as create:
            self.assertTrue(s.process_one()); s.process_one()
            self.assertEqual(create.call_count,1)
        with s.connect() as db:
            self.assertEqual(db.execute('select count(*) from alert_monitor_mappings').fetchone()[0],1)
        s.ingest({'version':'4','alerts':[{**alert,'status':'resolved','endsAt':'2026-10-23T10:10:00Z'}]})
        self.assertTrue(s.process_one())
        with s.connect() as db:
            row=db.execute('select alert_state,appmanager_resourceid from alert_monitor_mappings where fingerprint=?',('fp-one',)).fetchone()
            self.assertEqual(tuple(row),('resolved','9001'))
        s.ingest({'version':'4','alerts':[alert]})
        with patch.object(s.ME_CLIENT,'create_rest_monitor',return_value='9002') as create_again:
            s.process_one()
            self.assertEqual(create_again.call_count,0)
        with s.connect() as db:
            self.assertEqual(db.execute('select alert_state from alert_monitor_mappings where fingerprint=?',('fp-one',)).fetchone()[0],'firing')

    def test_dynamic_same_alertname_separate_fingerprints(self):
        s.INTEGRATION_MODE='dynamic_rest_monitor'
        a={**self.alert,'fingerprint':'fp-a'}; b={**self.alert,'fingerprint':'fp-b','labels':{**self.alert['labels'],'instance':'b'}}
        s.ingest({'version':'4','alerts':[a,b]})
        with patch.object(s.ME_CLIENT,'create_rest_monitor',side_effect=['1','2']) as create:
            s.process_one(); s.process_one()
        self.assertEqual(create.call_count,2)

if __name__=='__main__':unittest.main()
