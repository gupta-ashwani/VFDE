# Independent test set: how to get one and how to use it

Purpose: the bundled dataset and the verifier were written together, so its
numbers are optimistic. A test set produced by a different author, **without
sight of the rules or the verifier**, is a fairer check. This page has the
procedure and a prompt to give to a separate AI assistant.

## Procedure

1. Open a **fresh chat with a different assistant** (or a new session with no
   project context). Do not paste `rules.yaml`, the verifier, or the README.
   The less it knows about VFDE, the more independent the data is.
2. Paste the prompt below. If the assistant can run code, let it write a
   generator script and run it; otherwise ask for the files in parts.
3. Save the output in a new folder inside the project, e.g. `external_logs/`:
   `access.log`, `auth.log`, `ground_truth.csv` (and `benign_gotchas.csv` if
   provided). Keep this folder out of git unless you want to publish the data.
4. Run the evaluation. Labels written by someone else carry no VFDE rule
   names, so use window matching (auto-detected):

   ```bash
   python eval.py --logs external_logs --year 2025 --match window
   python cli.py analyze --logs external_logs --year 2025 --correlate --show
   ```

5. **Audit the labels before trusting the numbers.** Open `ground_truth.csv`
   and check 20-30 rows against the raw logs: does the IP really appear in the
   window, and does it do what the label says? A wrong label looks like a VFDE
   miss or false positive.
6. **Hold out.** Do not change `rules.yaml`, the verifier or the thresholds in
   response to this dataset and then re-report the same dataset. Report the
   first run as it is. If you do tune, say so, and generate a second fresh set
   to confirm.
7. Read the misses and false positives one by one. Each is a real gap in the
   tool, which is exactly what this exercise is for.

## What to expect

- Numbers should be **lower** than on the bundled dataset. That is a normal,
  honest result, not a failure.
- `window` matching is more lenient than `rules` matching: any non-Noise alert
  from the labelled IP inside start-5s .. end+10min counts as a detection, so
  a multi-stage attacker's other alerts can credit a neighbouring episode.
- The data is still synthetic. Describe it as an "independently generated
  synthetic dataset", not as real logs.
- An LLM can produce inconsistent logs (out-of-order timestamps, implausible
  response sizes). The self-check list in the prompt reduces this, but spot
  checks are still needed.

---

## Prompt to paste into the other assistant

```text
I am evaluating a defensive security tool that analyses web server and SSH
authentication logs. I need an INDEPENDENT labelled test dataset: realistic
synthetic log files plus a ground-truth file. This is test data for a
blue-team / SOC triage project. The deliverable is static text files only.

HARD RULES
- Produce log text and CSV only. No exploit code, no network code, nothing
  that sends traffic anywhere. If you write a generator script, it may only
  write local text files.
- Use only reserved documentation addresses for "external" clients:
  203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24. Use 10.0.0.0/8 or
  172.16.0.0/12 for internal/benign users. No real domains, no real IPs.
- Do not try to guess how my tool works. Design your own variety.

DELIVERABLES (four files)
1. access.log      web server log
2. auth.log        Linux SSH/sudo log
3. ground_truth.csv  the attack episodes
4. benign_gotchas.csv  harmless activity that could be mistaken for an attack

SIZE AND SPAN
- 48 hours of activity, starting 2025-03-14 00:00:00 UTC.
- About 10,000 to 20,000 lines in access.log, 400 to 1,000 in auth.log.
- 25 to 40 attack episodes in total, plus plenty of ordinary traffic.
- If a single response cannot hold this, write a Python generator that uses
  a fixed random seed and writes the files locally, and give me the script.

FORMAT 1: access.log (one request per line, exactly this layout)
203.0.113.9 - - [14/Mar/2025:12:00:01 +0000] "GET /products?id=12 HTTP/1.1" 200 5123 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" rt=0.120
  fields: client_ip - remote_user [dd/Mon/yyyy:HH:MM:SS +0000] "METHOD url HTTP/1.1"
          status bytes "referer" "user-agent" rt=<request seconds, 3 decimals>

FORMAT 2: auth.log (classic syslog, no year, host "web01")
Mar 14 12:00:01 web01 sshd[1021]: Failed password for root from 203.0.113.9 port 4022 ssh2
Mar 14 12:00:05 web01 sshd[1022]: Accepted password for deploy from 10.0.1.20 port 51234 ssh2
Mar 14 12:01:10 web01 sshd[1030]: Invalid user admin from 203.0.113.9 port 4101
Mar 14 12:02:00 web01 sudo:    alice : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls
  Also include the ordinary noise a real auth.log has (session opened/closed,
  "Connection closed by ... [preauth]", pam_unix lines, cron). Only some of
  these lines are relevant to attacks.

ATTACK EPISODES TO INCLUDE (vary counts, pacing, IPs and outcomes)
- Password guessing against SSH: fast scripted bursts and slow-and-low
  attempts; some end in a successful login, some never succeed; guessed
  usernames of different kinds.
- Directory/file enumeration against the web app: many requests for
  non-existent paths in a short time, with scanner-like or ordinary
  user-agents.
- Injection-style probes in query-string parameters: some produce server
  errors, unusually slow or unusually large responses (the attack "worked"),
  others return ordinary responses (the attack failed).
- Path-traversal-style requests for files outside the web root.
- Script-injection-style (XSS-like) payloads in query parameters.
- Multi-stage attackers: the same IP does reconnaissance, then probing, then
  SSH password guessing, then a login, spread over 10 to 90 minutes.
- Some attackers that rotate user-agents, pause between bursts, or mix their
  probes into ordinary-looking browsing.
- A few failed or half-hearted attempts (one or two probes, then nothing).

BENIGN TRAFFIC THAT MUST NOT BE LABELLED AS ATTACKS
Make this realistic and hard. Include at least these kinds, several times each:
- Normal browsing with a daily rhythm (quiet at night, busier in working
  hours), static assets, images, API calls, many different user-agents.
- Users who mistype a password a few times and then log in successfully.
- Legitimate searches and form inputs that merely contain words or
  punctuation that look suspicious (apostrophes in names, the word "select",
  "union", arithmetic, "--", angle brackets in a programming question).
- Search-engine crawlers and other bots that hit many missing URLs.
- A browser loading a page whose images are missing (a burst of 404s).
- Uptime monitors and health checks, including ones with unusual or
  tool-like user-agent strings.
- Administrators or on-call staff logging in at odd hours with valid keys.
- A vulnerability scanner run by the site owner from an internal IP
  (label it in benign_gotchas.csv, not in ground_truth.csv).
- Ordinary 500 errors and slow requests caused by the application itself.

REALISM REQUIREMENTS
- Timestamps non-decreasing within each file.
- Response sizes consistent per URL (a page is roughly the same size each
  time; dynamic pages vary a little). Static assets small. Occasional large
  downloads.
- Realistic status mix (mostly 200, some 301/304, a few 404, rare 500).
- Realistic request-time values (most under 0.5s; a few slow ones).
- Every attack IP should appear ONLY in its own episode(s); benign IPs must
  never appear in ground_truth.csv.

GROUND TRUTH FORMAT: ground_truth.csv
Header exactly: src_ip,technique,start,end,notes
- One row per attack episode. technique is a short plain label such as
  ssh_password_guessing, dir_enumeration, injection_probe, traversal_probe,
  xss_probe, multi_stage.
- start and end are the timestamps of the FIRST and LAST log line of that
  episode, ISO 8601 in UTC with a trailing Z (e.g. 2025-03-14T12:00:01Z).
- If one IP performs several stages, write one row per stage with its own
  start and end.
- Do not mention any detection tool, rule names or MITRE IDs. Label only
  what is actually in the logs.
- notes: one short sentence, e.g. "succeeded after 14 failures".

benign_gotchas.csv header: src_ip,description,start,end

SELF-CHECK BEFORE YOU FINISH (do this and report the results)
1. Every ground_truth.csv IP and time range actually appears in the logs.
2. No benign_gotchas IP appears in ground_truth.csv.
3. Timestamps are non-decreasing in both log files.
4. Line counts per file, number of episodes per technique, and the share of
   attack lines versus all lines.
5. List any place where a label might be wrong or ambiguous.
```
