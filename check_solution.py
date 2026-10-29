"""Keep these checks unchanged. Run all, or select LoginChecks/DownloadChecks."""
import copy
import csv
import json
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path
from analyze_case import find_login_sequences, correlate_downloads
from evidence_tools import load_case, parse_time, read_evidence, utc_text

BASE = Path(__file__).resolve().parent
T = parse_time('2026-10-20T09:05:00Z')

def auth(eid, seconds, result='FAIL', user='u', ip='192.0.2.1', host='H', session='S'):
    return {'event_id': eid, 'timestamp': T + timedelta(seconds=seconds),
            'username': user, 'source_ip': ip, 'host': host, 'result': result,
            'session_id': session if result == 'SUCCESS' else ''}

def alert(eid='OK', session='S', user='u', host='H'):
    return {'username': user, 'source_ip': '192.0.2.1', 'host': host,
            'session_id': session, 'success_id': eid, 'success_time': T,
            'failure_ids': ['E1', 'E2', 'E3']}

def download(eid, seconds, size=10, **overrides):
    row = {'event_id': eid, 'timestamp': T + timedelta(seconds=seconds),
           'username': 'u', 'host': 'H', 'session_id': 'S', 'action': 'DOWNLOAD',
           'path': '/training/test.dat', 'bytes': size, 'result': 'SUCCESS'}
    row.update(overrides)
    return row

class LoginChecks(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(find_login_sequences([]), [])

    def test_unsorted_rows_and_evidence_order(self):
        rows = [auth('OK',0,'SUCCESS'),auth('E3',-60),auth('E1',-180),auth('E2',-120)]
        self.assertEqual(find_login_sequences(rows), [alert()])

    def test_window_includes_exactly_five_minutes(self):
        rows = [auth('E1',-300),auth('E2',-2),auth('E3',-1),auth('OK',0,'SUCCESS')]
        self.assertEqual(find_login_sequences(rows), [alert()])

    def test_outside_equal_and_future_failures_do_not_count(self):
        for offset in [-301,0,1]:
            with self.subTest(offset=offset):
                rows=[auth('E1',offset),auth('E2',-2),auth('E3',-1),auth('OK',0,'SUCCESS')]
                self.assertEqual(find_login_sequences(rows), [])

    def test_account_ip_and_host_must_all_match(self):
        for change in [{'user':'other'},{'ip':'192.0.2.2'},{'host':'H2'}]:
            with self.subTest(change=change):
                rows=[auth('E1',-3,**change),auth('E2',-2),auth('E3',-1),auth('OK',0,'SUCCESS')]
                self.assertEqual(find_login_sequences(rows), [])

    def test_failures_without_success_are_not_alerts(self):
        self.assertEqual(find_login_sequences([auth('E1',-3),auth('E2',-2),auth('E3',-1)]), [])

    def test_parameters_and_each_success_window(self):
        rows=[auth('E1',-180),auth('E2',-120),auth('E3',-60),auth('OK',0,'SUCCESS'),auth('OK2',30,'SUCCESS',session='S2')]
        self.assertEqual(len(find_login_sequences(rows)),2)
        self.assertEqual(find_login_sequences(rows,min_failures=4),[])
        self.assertEqual(find_login_sequences(rows,window_minutes=1),[])

    def test_ties_and_output_order(self):
        rows=[auth('OK2',1,'SUCCESS'),auth('OK',0,'SUCCESS'),auth('E3',-1),auth('E2',-2),auth('E1',-2)]
        out=find_login_sequences(rows)
        self.assertEqual([x['success_id'] for x in out],['OK','OK2'])
        self.assertEqual(out[0]['failure_ids'],['E1','E2','E3'])

    def test_does_not_mutate_input(self):
        rows=[auth('OK',0,'SUCCESS'),auth('E3',-1),auth('E2',-2),auth('E1',-3)]
        snapshot=copy.deepcopy(rows)
        find_login_sequences(rows)
        self.assertEqual(rows,snapshot)

class DownloadChecks(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(correlate_downloads([],[]),[])

    def test_keeps_alert_with_no_downloads(self):
        self.assertEqual(correlate_downloads([alert()],[]),
                         [dict(alert(),download_ids=[],download_count=0,total_bytes=0)])

    def test_requires_session_account_host_action_and_success(self):
        rows=[download('F1',1), download('WRONG_SESSION',1,session_id='OTHER'),
              download('WRONG_USER',1,username='other'),download('WRONG_HOST',1,host='H2'),
              download('LIST',1,action='LIST'),download('FAILED',1,result='FAIL')]
        out=correlate_downloads([alert()],rows)[0]
        self.assertEqual(out['download_ids'],['F1'])
        self.assertEqual(out['total_bytes'],10)

    def test_closed_window_includes_zero_and_ten_minutes(self):
        rows=[download('BEFORE',-1),download('END',600,20),download('START',0,10),download('AFTER',601)]
        out=correlate_downloads([alert()],rows)[0]
        self.assertEqual(out['download_ids'],['START','END'])
        self.assertEqual((out['download_count'],out['total_bytes']),(2,30))

    def test_ranking_event_ties_and_repeated_paths(self):
        rows=[download('B',2,4),download('A',2,3),download('C',1,20,session_id='S2')]
        out=correlate_downloads([alert(),alert('OK2','S2')],rows)
        self.assertEqual([x['success_id'] for x in out],['OK2','OK'])
        self.assertEqual(out[1]['download_ids'],['A','B'])
        self.assertEqual(out[1]['download_count'],2)

    def test_configurable_followup(self):
        rows=[download('IN',60),download('OUT',61)]
        self.assertEqual(correlate_downloads([alert()],rows,followup_minutes=1)[0]['download_ids'],['IN'])

    def test_does_not_mutate_either_input(self):
        alerts=[alert()]; rows=[download('B',2),download('A',1)]
        snapshot=copy.deepcopy((alerts,rows))
        out=correlate_downloads(alerts,rows)
        self.assertEqual((alerts,rows),snapshot)
        self.assertIsNot(out[0],alerts[0])

class EvidenceChecks(unittest.TestCase):
    def test_equivalent_time_offsets_and_missing_offset(self):
        self.assertEqual(parse_time('2026-10-20T10:01:00+01:00'),parse_time('2026-10-20T09:01:00Z'))
        with self.assertRaises(ValueError): parse_time('2026-10-20T09:01:00')

    def test_supplied_quality_counts_and_duplicates(self):
        auth_rows,file_rows,audit=load_case(BASE)
        self.assertEqual((len(auth_rows),len(file_rows)),(54,30))
        for name,expected,duplicate in [('auth_log.csv',(60,54,1,5),'A003'),('file_log.csv',(35,30,1,4),'F001')]:
            item=audit[name]
            self.assertEqual((item['data_rows'],item['accepted'],len(item['duplicates']),len(item['rejected'])),expected)
            self.assertEqual(item['duplicates'][0]['event_id'],duplicate)

    def test_hash_mismatch_stops_analysis(self):
        with tempfile.TemporaryDirectory() as folder:
            destination=Path(folder)
            for name in ['auth_log.csv','file_log.csv','evidence_manifest.json']:
                (destination/name).write_bytes((BASE/name).read_bytes())
            with (destination/'auth_log.csv').open('ab') as stream: stream.write(b'\n')
            with self.assertRaisesRegex(ValueError,'SHA-256 mismatch'): load_case(destination)

    def test_conflicting_ids_are_not_silently_discarded(self):
        with tempfile.TemporaryDirectory() as folder:
            target=Path(folder)/'file.csv'
            rows=[download('REPEATED',0,1),download('REPEATED',0,2)]
            from evidence_tools import FILE_FIELDS
            with target.open('w',newline='',encoding='utf-8') as stream:
                writer=csv.DictWriter(stream,fieldnames=FILE_FIELDS)
                writer.writeheader()
                for row in rows:
                    row['timestamp']=utc_text(row['timestamp']);writer.writerow(row)
            with self.assertRaisesRegex(ValueError,'conflicting event ID'): read_evidence(target,'file')

class CaseChecks(unittest.TestCase):
    def test_supplied_case(self):
        auth_rows,file_rows,_=load_case(BASE)
        out=correlate_downloads(find_login_sequences(auth_rows),file_rows)
        self.assertEqual([(x['success_id'],x['failure_ids'],x['download_ids'],x['total_bytes']) for x in out],
          [('A005',['A002','A003','A004'],['F001','F002','F003'],5509120),
           ('A018',['A015','A016','A017'],['F013'],2048),
           ('A014',['A011','A012','A013'],[],0)])

if __name__ == '__main__':
    unittest.main(verbosity=2)
