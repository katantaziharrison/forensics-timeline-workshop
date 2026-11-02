# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section

| Source | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| --- | --- | --- | --- | --- |
| auth_log.csv | [60] | [54] | [1] | [5] |
| file_log.csv | [35] | [30] | [1] | [4] |

- SHA-256 check outcome and what it establishes: [fill]
- One rejected event ID and the exact rejection reason: [A901, "missing username"]
- Number of flagged successful sessions: [54]

| Success ID | Account | Session | Supporting failure IDs | Download IDs | Event count | Total bytes |
| --- | --- | --- | --- | --- | --- | --- |
| A005 |Analyst01 | s-104| A002,A003,A004|F001, F003,F002|3| 5509120|
|A018|analyst02|S-304|A015,A016,A017|013|1|2048|
|A014|backup_svc|S-204|A011,A012,A013| |0|0|    
        
       

## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp | UTC timestamp | What the row records |
| --- | --- | --- | --- |
| auth_log.csv/A002 | Failed login | 2026-10-20T08:58:00Z | 2026-10-20T08:58:00Z|
|auth_log.csv/A003  | Failed login | 2026-10-20T09:00:00Z | 2026-10-20T09:00:00Z|
|auth_log.csv/A004  | Failed login | 2026-10-20T10:01:00+01:00 | 2026-10-20T09:01:00Z|
|auth_log.csv/A005  | Successful login| 2026-10-20T09:03:00Z| 2026-10-20T09:03:00Z|
|file_log.csv/F001  | Successful download| 2026-10-20T09:05:00Z | 2026-10-20T09:05:00Z|
|file_log.csv/F002  | Successful download| 2026-10-20T10:07:00+01:00| 2026-10-20T09:07:00Z|
|file_log.csv/F003  | Successful download| 2026-10-20T09:13:00Z| 2026-10-20T09:13:00Z|

- Manual sum of download bytes, showing the addition: [Manual sum of download bytes: F001 + F002 + F003 = 5,242,880 + 262,144 + 4,096 = 5,509,120 bytes.]
- A001 versus A002: which qualifies for the A005 window and why? [A002 qualifies because its timestamp, 08:58:00Z, is exactly five minutes before A005 at 09:03:00Z. The lower boundary is inclusive. A001 at 08:57:59Z falls outside by one second.]
- F003 versus F004: which qualifies for the A005 follow-up and why? [F003 qualifies at 09:13:00Z, exactly ten minutes after A005. The upper boundary is inclusive. F004 at 09:13:01Z falls outside by one second.]
- Why F005 is excluded even though the account matches: [Its session is S-OTHER, whereas A005’s session is S-104. Username, host, and session must all match.]
- One +01:00 timestamp and its equivalent UTC time: [A004’s 2026-10-20T10:01:00+01:00 equals 2026-10-20T09:01:00Z; subtract one hour.]
- One limitation of excluding malformed records: [ome rejected records could represent relevant activity. Excluding them can leave gaps and undercount events, so the findings describe only the accepted evidence.]

## Checks actually run

Command, date and actual final result (paste output, including failures if any):
date '+%Y-%m-%d %H:%M:%S %Z' python3 -B check_solution.py 2>&1
```
2026-11-02 14:20:54 CET
test_supplied_case (__main__.CaseChecks) ... ok
test_closed_window_includes_zero_and_ten_minutes (__main__.DownloadChecks) ... ok
test_configurable_followup (__main__.DownloadChecks) ... ok
test_does_not_mutate_either_input (__main__.DownloadChecks) ... ok
test_empty (__main__.DownloadChecks) ... ok
test_keeps_alert_with_no_downloads (__main__.DownloadChecks) ... ok
test_ranking_event_ties_and_repeated_paths (__main__.DownloadChecks) ... ok
test_requires_session_account_host_action_and_success (__main__.DownloadChecks) ... ok
test_conflicting_ids_are_not_silently_discarded (__main__.EvidenceChecks) ... ok
test_equivalent_time_offsets_and_missing_offset (__main__.EvidenceChecks) ... ok
test_hash_mismatch_stops_analysis (__main__.EvidenceChecks) ... ok
test_supplied_quality_counts_and_duplicates (__main__.EvidenceChecks) ... ok
test_account_ip_and_host_must_all_match (__main__.LoginChecks) ... ok
test_does_not_mutate_input (__main__.LoginChecks) ... ok
test_empty (__main__.LoginChecks) ... ok
test_failures_without_success_are_not_alerts (__main__.LoginChecks) ... ok
test_outside_equal_and_future_failures_do_not_count (__main__.LoginChecks) ... ok
test_parameters_and_each_success_window (__main__.LoginChecks) ... ok
test_ties_and_output_order (__main__.LoginChecks) ... ok
test_unsorted_rows_and_evidence_order (__main__.LoginChecks) ... ok
test_window_includes_exactly_five_minutes (__main__.LoginChecks) ... ok

----------------------------------------------------------------------
Ran 21 tests in 0.011s

OK
```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

> [Session S-104 for analyst01 had the highest flagged download total, with 5,509,120 bytes across F001–F003 after failures A002–A004 and success A005. These events warrant investigation but do not establish identity or theft, and matching manifest hashes do not prove the logs’ authenticity or completeness]

One claim we corrected or independently verified, with event IDs:

[We corrected the claim that the highest download total proves analyst01 was the attacker and stole evidence. Events A002–A004 show failed logins before success A005, followed by qualifying downloads F001–F003 totaling 5,509,120 bytes in session S-104. These records support further investigation but do not establish who controlled the account or prove theft.]

Final 180-220 word finding, reviewed and edited by the pair:

[write here]

It must cite evidence IDs, separate observation from inference, include a
comparison session, two limitations, one benign explanation and two next
evidence requests. Do not claim that an account or IP identifies a person.

## AI use and pair review

- Names of both partners: [fill]
- GenAI tool/ChatGPT date and displayed model: [fill]
- Prompts used and what they produced: [fill]
- One follow-up question or correction, with a short response excerpt: [fill]
- Results of code and evidence checks performed: [fill]


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
