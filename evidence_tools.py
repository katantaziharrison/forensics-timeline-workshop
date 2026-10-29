"""Supplied evidence handling helpers. Leave this file unchanged for the lab."""
import csv
import hashlib
import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path

AUTH_FIELDS = ['event_id', 'timestamp', 'username', 'source_ip', 'host', 'result', 'session_id']
FILE_FIELDS = ['event_id', 'timestamp', 'username', 'host', 'session_id', 'action', 'path', 'bytes', 'result']

def parse_time(value):
    """Require an explicit UTC offset and return an aware UTC datetime."""
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.utcoffset() is None:
        raise ValueError('timestamp needs Z or an explicit UTC offset')
    return parsed.astimezone(timezone.utc)

def utc_text(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')

def read_evidence(path, kind):
    """Return accepted records and a row-level audit; never edit source files.

    Strip outer whitespace, validate required fields, convert timestamp/bytes,
    skip identical repeated event IDs, and retain the first valid occurrence.
    Conflicting records with the same event ID stop the analysis for review.
    Output order remains the input order; student functions must sort copies.
    """
    fields = AUTH_FIELDS if kind == 'auth' else FILE_FIELDS
    accepted, seen = [], {}
    audit = {'data_rows': 0, 'accepted': 0, 'duplicates': [], 'rejected': []}
    with Path(path).open(newline='', encoding='utf-8') as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != fields:
            raise ValueError(f'{Path(path).name}: unexpected CSV header')
        for row_number, raw in enumerate(reader, start=2):
            audit['data_rows'] += 1
            event_id = raw.get('event_id') or '(missing)'
            try:
                if None in raw or any(value is None for value in raw.values()):
                    raise ValueError('wrong number of CSV fields')
                row = {key: value.strip() for key, value in raw.items()}
                for key in ['event_id', 'timestamp', 'username', 'host', 'result']:
                    if not row[key]:
                        raise ValueError(f'missing {key}')
                if row['result'] not in {'FAIL', 'SUCCESS'}:
                    raise ValueError('result must be FAIL or SUCCESS')
                row['timestamp'] = parse_time(row['timestamp'])
                if kind == 'auth':
                    ipaddress.ip_address(row['source_ip'])
                    if row['result'] == 'SUCCESS' and not row['session_id']:
                        raise ValueError('successful login needs session_id')
                else:
                    if not row['session_id'] or not row['path']:
                        raise ValueError('file event needs session_id and path')
                    if row['action'] not in {'DOWNLOAD', 'LIST'}:
                        raise ValueError('action must be DOWNLOAD or LIST')
                    row['bytes'] = int(row['bytes'])
                    if row['bytes'] < 0:
                        raise ValueError('bytes must be nonnegative')
            except ValueError as error:
                audit['rejected'].append({'csv_row': row_number, 'event_id': event_id, 'reason': str(error)})
                continue
            event_id = row['event_id']
            if event_id in seen:
                if seen[event_id] != row:
                    raise ValueError(f'{Path(path).name}: conflicting event ID {event_id}; review before continuing')
                audit['duplicates'].append({'csv_row': row_number, 'event_id': event_id})
                continue
            seen[event_id] = row
            accepted.append(row)
    audit['accepted'] = len(accepted)
    return accepted, audit

def load_case(base):
    base = Path(base)
    manifest = json.loads((base / 'evidence_manifest.json').read_text(encoding='utf-8'))
    hashes = {}
    for name in ['auth_log.csv', 'file_log.csv']:
        actual = hashlib.sha256((base / name).read_bytes()).hexdigest()
        if actual != manifest['files'][name]:
            raise ValueError(f'{name}: SHA-256 mismatch. Re-extract the original data; do not edit the manifest.')
        hashes[name] = actual
    auth, auth_audit = read_evidence(base / 'auth_log.csv', 'auth')
    files, file_audit = read_evidence(base / 'file_log.csv', 'file')
    return auth, files, {'sha256': hashes, 'auth_log.csv': auth_audit, 'file_log.csv': file_audit}

def write_json(path, value):
    def encode(item):
        if isinstance(item, datetime):
            return utc_text(item)
        raise TypeError(f'Cannot serialise {type(item).__name__}')
    Path(path).write_text(json.dumps(value, indent=2, default=encode) + '\n', encoding='utf-8')
