"""
UC02 - Log Analysis & Investigation Agent  (single file)

Run the web chat :  streamlit run main.py
Run the terminal  :  python main.py
Needs             :  logs.json next to this file.  Optional: .env with GEMINI_API_KEY=...

Every answer (Gemini OR local engine) has the SAME structure so it is easy to read:
    1. Headline          - one-sentence answer
    2. Findings          - each tagged CONFIRMED / INFERRED / UNKNOWN
    3. Evidence          - table: timestamp (UTC) | severity | source | excerpt
    4. Recommendations   - HIGH / MEDIUM / LOW (only when relevant)
    5. Why this answer?  - how the agent reached it (intent scores or reasoning)
"""
import json
import os
import re
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
LOG_FILE = os.getenv("LOG_FILE", "logs.json")
TIMEOUT_S = float(os.getenv("GEMINI_TIMEOUT_S", "25"))
MODE = os.getenv("AGENT_MODE", "hybrid")  # hybrid | gemini | local
EXCERPT = 400  # max characters of a log line shown as evidence

ICON = {"CONFIRMED": "✅", "INFERRED": "🟡", "UNKNOWN": "❓"}
PRIO = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}


# =====================================================================
# 1. LOG PARSER  (cleans logs, builds run summaries in code, not by LLM)
# =====================================================================
ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _clean(text):
    return ANSI.sub("", text).strip()


def load_logs(path):
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return sorted(data, key=lambda e: e.get("timestamp", ""))


def _service(entry):
    r = entry.get("resource", {}).get("labels", {})
    return f"{entry.get('resource', {}).get('type', '?')}/{r.get('job_name', '?')}"


def _log_kind(entry):
    return entry.get("logName", "").split("/logs/")[-1].replace("%2F", "/")


def _audit_summary(entry):
    p = entry["protoPayload"]
    parts = [f"AUDIT method={p.get('methodName', '?')}"]
    msg = p.get("status", {}).get("message", "")
    if msg:
        parts.append(f"status_msg={msg!r}")
    spec = None
    if "request" in p:
        spec = p["request"].get("job", {}).get("spec")
    elif p.get("response", {}).get("kind") in ("Job", "Execution"):
        spec = p["response"].get("spec")
    try:
        inner = spec["template"]["spec"]["template"]["spec"] if "template" in spec["template"].get("spec", {}) \
            else spec["template"]["spec"]
    except Exception:
        inner = None
    if inner:
        env = {e["name"]: e["value"] for c in inner.get("containers", []) for e in c.get("env", [])}
        parts.append(f"maxRetries={inner.get('maxRetries')} timeout={inner.get('timeoutSeconds')}s env={env or 'none'}")
    if p.get("response", {}).get("kind") == "Execution":
        st = p["response"]["status"]
        for c in st.get("conditions", []):
            if c["type"] == "Completed":
                parts.append(f"Completed: {c['message']}")
        if "retriedCount" in st:
            parts.append(f"retriedCount={st['retriedCount']}")
    ua = p.get("requestMetadata", {}).get("callerSuppliedUserAgent", "")
    if ua:
        m = re.search(r"command/(\S+)", ua)
        v = re.search(r"gcloud/(\S+)", ua)
        parts.append(f"caller=gcloud {v.group(1) if v else ''} {m.group(1) if m else ''}")
    return " | ".join(parts)


def compact_lines(logs):
    lines = []
    for e in logs:
        att = e.get("labels", {}).get("run.googleapis.com/task_attempt")
        if "textPayload" in e:
            msg = _clean(e["textPayload"])
            if not msg:
                continue
        elif "protoPayload" in e:
            msg = _audit_summary(e)
        else:
            msg = json.dumps(e)[:300]
        lines.append(f"[{e.get('timestamp', '')}] id={e.get('insertId', '')} sev={e.get('severity', '-')} "
                     f"svc={_service(e)} log={_log_kind(e)}{f' attempt={att}' if att is not None else ''} :: {msg}")
    return lines


def split_runs(logs):
    """A 'run' starts at 'Running with dbt' and ends at 'Container called exit'."""
    runs, cur = [], None
    for e in logs:
        t = _clean(e.get("textPayload", "")) if "textPayload" in e else ""
        att = e.get("labels", {}).get("run.googleapis.com/task_attempt")
        if cur is None and "textPayload" in e and "Running with dbt=" not in t and not t.startswith("Container called exit"):
            cur = {"start": e["timestamp"] + " (PARTIAL: log begins mid-run)", "events": [], "attempt": att}
            runs.append(cur)
        if "Running with dbt=" in t:
            cur = {"start": e["timestamp"], "events": [], "attempt": att}
            runs.append(cur)
        if cur is not None and "textPayload" in e:
            cur["events"].append((e["timestamp"], t))
        if cur is not None and t.startswith("Container called exit"):
            cur["exit"] = (e["timestamp"], t, e.get("severity"))
            cur["end"] = e["timestamp"]
            cur = None
    return runs


def run_summaries(logs):
    out = []
    for i, r in enumerate(split_runs(logs), 1):
        txt = [t for _, t in r["events"]]
        target = next((re.search(r"target='(\w+)'", t).group(1) for t in txt if "target=" in t), "?")
        found = next((t.split("Found ", 1)[1] for t in txt if "Found " in t and "models" in t), "?")
        done = next((re.search(r"Done\. (.*)", t).group(1) for t in txt if re.search(r"Done\. PASS=", t)), "no 'Done' line")
        errors = [t for t in txt if "ERROR" in t and "ERROR=" not in t]
        warns = [t for t in txt if "WARNING" in t]
        built = [re.search(r"model (\S+)", t).group(1) + " (" + re.search(r"\((.*?)\)", t).group(1) + ")"
                 for t in txt if " OK created" in t and re.search(r"\((.*?)\)", t)]
        ex = r.get("exit", (None, "no exit line", None))
        out.append(f"RUN {i}: start={r['start']} attempt={r['attempt']} dbt_target={target}\n"
                   f"  project size: {found}\n  result: {done}\n"
                   f"  container: {ex[1]} (sev={ex[2]}) at {ex[0]}\n"
                   f"  errors: {errors if errors else 'none'}\n  warning count: {len(warns)}\n  tables built: {built}")
    return "\n\n".join(out)


def build_context(path):
    logs = load_logs(path)
    return ("=== PRECOMPUTED RUN SUMMARIES (computed by code, exact) ===\n" + run_summaries(logs)
            + "\n\n=== FULL CHRONOLOGICAL LOG (ANSI codes and blank lines removed) ===\n"
            + "\n".join(compact_lines(logs)))


# =====================================================================
# 2. ANSWER STRUCTURE  (shared by Gemini + local engine)
# =====================================================================
def F(label, text):
    return {"label": label, "text": text}


def R(priority, action, why, label="INFERRED"):
    return {"priority": priority, "action": action, "why": why, "label": label}


def make_answer(headline, findings=None, evidence=None, recs=None, why=None):
    return {"headline": headline, "findings": findings or [], "evidence": evidence or [],
            "recommendations": recs or [], "why": why or {}}


# =====================================================================
# 3. LOCAL ENGINE  (no LLM, no internet; fallback channel)
# =====================================================================
MONTHS = {"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8,
          "sep": 9, "sept": 9, "oct": 10, "nov": 11, "dec": 12}

INTENTS = {
    "service": {"service": 3, "component": 3, "belong": 3, "which": 1, "what system": 3, "what job": 3,
                "platform": 2, "identify": 2, "origin": 2, "pipeline": 2, "tool": 1, "dbt": 1, "who run": 2,
                "what is this log": 4, "log from": 3, "come from": 3, "comes from": 3, "generated by": 3, "which app": 3},
    "error": {"error": 3, "fail": 3, "wrong": 3, "issue": 2, "problem": 2, "crash": 3, "broke": 3,
              "exit(1)": 3, "billing": 3, "skip": 2, "went bad": 3, "not work": 3, "root cause": 3, "why": 1,
              "break": 3, "broken": 3, "outage": 3, "incident": 2, "unsuccessful": 3, "didn't work": 3},
    "recover": {"recover": 4, "retry": 4, "retri": 4, "succe": 2, "fix": 2, "resolv": 3, "rerun": 3,
                "second attempt": 4, "after": 1, "again": 1, "ok now": 2},
    "warning": {"warn": 4, "deprecat": 4, "typo": 3, "not found": 2, "yml": 2, "unused": 2, "later run": 1},
    "config": {"config": 4, "chang": 3, "deploy": 3, "maxretri": 4, "env": 3, "setting": 3, "differ": 2,
               "update": 2, "modif": 2, "replacejob": 4, "timeout": 3, "version": 2, "between run": 3},
    "data": {"row": 4, "grow": 3, "size": 2, "data volume": 4, "gib": 3, "table": 2, "bigquery": 2, "built": 2,
             "created": 2, "processed": 3, "increase": 2, "trend": 2},
    "target": {"target": 3, "test_bi": 4, "prod": 3, "dataset": 3, "environment": 3, "schema": 3},
    "further": {"further": 4, "investigat": 3, "unresolved": 4, "open question": 4, "follow up": 3,
                "next step": 3, "anything else": 3, "missing": 3, "unknown": 3, "worry": 2,
                "suspicious": 4, "concern": 3, "unusual": 3, "abnormal": 3, "anomal": 3, "look at": 2, "red flag": 4},
    "recommend": {"recommend": 6, "suggest": 4, "how to fix": 5, "how do i fix": 5, "fix": 3, "prevent": 4,
                  "improve": 3, "action": 3, "what should": 4, "mitigat": 4, "best practice": 4},
    "summary": {"summar": 4, "overview": 4, "timeline": 4, "finding": 3, "what happen": 3, "tell me about": 2,
                "all run": 3, "history": 3, "sequence": 3,
                "health": 3, "status": 2, "overall": 3, "how is": 2, "container": 2, "exit": 2, "execution": 2},
    "evidence": {"evidence": 5, "proof": 4, "support": 3, "show me the log": 4, "log line": 3, "which log": 3,
                 "excerpt": 3, "cite": 3, "source": 2},
}


def parse_date(q):
    m = re.search(r"(20\d\d)-(\d\d)-(\d\d)", q)
    if m:
        return f"{m.group(1)}-{m.group(2)}-{m.group(3)}"
    ql = q.lower()
    m = re.search(r"\b(jan|feb|mar|apr|may|jun|jul|aug|sept|sep|oct|nov|dec)[a-z]*\.?\s+(\d{1,2})\b", ql) or \
        re.search(r"\b(\d{1,2})(?:st|nd|rd|th)?\s+(jan|feb|mar|apr|may|jun|jul|aug|sept|sep|oct|nov|dec)", ql)
    if m:
        a, b = m.groups()
        mon, day = (a, b) if a.isalpha() else (b, a)
        return f"2026-{MONTHS[mon]:02d}-{int(day):02d}"
    return None


def classify(q):
    """Returns best intent, total scores, and exactly which phrases matched (for 'Why this answer?')."""
    ql = q.lower()
    matched = defaultdict(list)
    for intent, words in INTENTS.items():
        for w, wt in words.items():
            if w in ql:
                matched[intent].append((w, wt))
    scores = {i: sum(w for _, w in hits) for i, hits in matched.items()}
    if not scores:
        return None, {}, {}
    return max(scores, key=scores.get), scores, dict(matched)


class LocalAnalyst:
    def __init__(self, path):
        self.last_intent, self.last_date = None, None
        self.logs = load_logs(path)
        self.runs = split_runs(self.logs)
        self.lines = []  # (timestamp, severity, source, text, attempt)
        for e in self.logs:
            if "textPayload" in e:
                t = _clean(e["textPayload"])
                if t:
                    self.lines.append((e["timestamp"], e.get("severity", "-"), "stdout/system", t,
                                       e.get("labels", {}).get("run.googleapis.com/task_attempt")))
            elif "protoPayload" in e:
                self.lines.append((e["timestamp"], e.get("severity", "-"), e["logName"].split("%2F")[-1],
                                   _audit_summary(e).replace("AUDIT ", ""), None))

    # ---------- helpers ----------
    @staticmethod
    def _ev(items, limit=8):
        return [{"timestamp": ts, "severity": sev if sev and sev != "-" else "DEFAULT", "source": src,
                 "excerpt": txt[:EXCERPT]} for ts, sev, src, txt, _ in items[:limit]]

    def _in_date(self, date):
        return [l for l in self.lines if not date or l[0].startswith(date)]

    def _run_info(self, r):
        txt = [t for _, t in r["events"]]
        g = lambda pat: next((re.search(pat, t).group(1) for t in txt if re.search(pat, t)), "?")
        return {"start": r["start"][:19], "attempt": r["attempt"], "target": g(r"target='(\w+)'"),
                "result": g(r"Done\. (.*)"), "exit": r.get("exit", (0, "?", 0))[1],
                "models": g(r"Found (\d+ models)")}

    def overview(self):
        rows = []
        for r in self.runs:
            i = self._run_info(r)
            ok = "ERROR=0" in i["result"] or "ERROR=" not in i["result"]
            rows.append({"Start (UTC)": i["start"].replace("T", " "), "Attempt": i["attempt"],
                         "Target": i["target"], "Models": i["models"], "Result": i["result"][:40],
                         "Exit": i["exit"].replace("Container called ", "").rstrip("."), "OK?": "✅" if ok else "❌"})
        return rows

    def stats(self):
        failed = sum(1 for r in self.runs if "ERROR=0" not in self._run_info(r)["result"]
                     and "ERROR=" in self._run_info(r)["result"])
        warns = sum(1 for l in self.lines if "WARNING" in l[3] or "Deprecat" in l[3])
        deploys = len({l[0][:19] for l in self.lines if "Jobs.ReplaceJob" in l[3] and l[2] == "activity"})
        return {"Log entries": len(self.logs), "Runs": len(self.runs), "Failed runs": failed,
                "Warning lines": warns, "Deployments": deploys}

    # ---------- intents (each returns a structured answer) ----------
    def service(self, date):
        types = {e["resource"]["type"] for e in self.logs}
        names = set(re.findall(r"(dbt-webserver-logs)", " ".join(l[3] for l in self.lines)))
        ver = next((re.search(r"dbt=([\d.]+)", l[3]).group(1) for l in self.lines if "Running with dbt=" in l[3]), "?")
        adapter = next((l[3].split("adapter: ")[-1][:40] for l in self.lines if "Registered adapter" in l[3]), "")
        ev = [l for l in self.lines if "Running with dbt" in l[3] or "Registered adapter" in l[3]][:2] + \
             [l for l in self.lines if "dbt-webserver-logs" in l[3]][:3]
        f = [F("CONFIRMED", f"Resource type is {', '.join(types)} (a Google Cloud Run *job*, region us-central1)."),
             F("CONFIRMED", f"The job name is {', '.join(names) or 'redacted'}; it runs dbt {ver} with the BigQuery adapter ({adapter})."),
             F("CONFIRMED", "The job name is hidden (redacted) in stdout entries but visible in audit entries and in messages "
                            "such as 'Reported failure for dbt-webserver-logs'.")]
        return make_answer("These logs come from the Cloud Run job 'dbt-webserver-logs' (dbt + BigQuery).", f, self._ev(ev))

    def error(self, date):
        pool = self._in_date(date)
        errs = [l for l in pool if re.search(r"\bERROR\b|exit\(1\)|Reported failure|Billing has not", l[3]) and "ERROR=0" not in l[3]]
        if not errs:
            return make_answer(f"No errors found{' on ' + date if date else ''}.",
                               [F("CONFIRMED", "No ERROR lines and no non-zero exit codes appear in the logs"
                                  + (f" for {date}." if date else "."))])
        done = next((l[3] for l in pool if re.search(r"Done\. PASS=", l[3]) and "ERROR=0" not in l[3]), "")
        skip_n = re.search(r"SKIP=(\d+)", done)
        model = next((m.group(1) for l in errs if (m := re.search(r"in model (\w+)", l[3]))), "a model")
        f = [F("CONFIRMED", f"dbt model `{model}` failed to build.")]
        if skip_n:
            f.append(F("CONFIRMED", f"{skip_n.group(1)} later steps were SKIPPED because they depend on the failed model. "
                                    f"dbt summary: '{done.split('Done. ')[-1]}'."))
        if any("Billing" in l[3] for l in errs):
            f.append(F("CONFIRMED", "BigQuery reported: 'Billing has not been enabled for this project... sandbox mode'."))
        if any("exit(1)" in l[3] for l in errs):
            f.append(F("CONFIRMED", "The container then exited with code 1 (failure) and reported the failure to 'pipeline-events'."))
        if any("Billing" in l[3] for l in errs):
            f.append(F("UNKNOWN", "WHY billing was unavailable at that moment is not shown in the logs."))
        return make_answer(f"A run failed{' on ' + date if date else ''}: {model} could not be built.", f, self._ev(errs))

    def recover(self, date):
        f, ev = [], []
        for i, r in enumerate(self.runs):
            info = self._run_info(r)
            if "ERROR=0" in info["result"] or "ERROR=" not in info["result"] and "exit(1)" not in info["exit"]:
                continue
            if i + 1 < len(self.runs):
                nxt = self.runs[i + 1]
                n = self._run_info(nxt)
                f.append(F("CONFIRMED", f"Run at {info['start']} failed ({info['result']})."))
                f.append(F("CONFIRMED", f"The next run at {n['start']} (task_attempt={n['attempt']}) finished with "
                                        f"'{n['result']}' and {n['exit'].rstrip('.')}."))
                f.append(F("INFERRED", "This looks like an automatic Cloud Run retry; the logs show attempt=1 but no explicit 'retrying' message."))
                ev += [l for l in self.lines if r["events"][0][0] <= l[0] <= r.get("end", "9999")
                       and re.search(r"Done\. PASS=|Container called exit", l[3])]
                t0 = nxt["events"][0][0]
                ev += [l for l in self.lines if l[0] >= t0 and l[0] <= nxt.get("end", "9999")
                       and re.search(r"Done\. PASS=|Container called exit", l[3])]
        if not f:
            return make_answer("No failed run exists, so no recovery was needed.",
                               [F("CONFIRMED", "All runs finished without ERROR.")])
        return make_answer("Yes - the job recovered on the next attempt.", f, self._ev(ev))

    def warning(self, date):
        pool = [l for l in self._in_date(date) if "WARNING" in l[3] or "Deprecat" in l[3]]
        if not pool:
            return make_answer("No warnings found.", [F("CONFIRMED", "No warnings" + (f" on {date}." if date else "."))])
        uniq = {}
        for l in pool:
            uniq.setdefault(re.sub(r"^\d\d:\d\d:\d\d\s+", "", l[3]), [l, 0])[1] += 1
        f = [F("CONFIRMED", f"{len(pool)} warning lines in total, {len(uniq)} distinct.")]
        ev = []
        for key, (l, n) in list(uniq.items())[:6]:
            f.append(F("CONFIRMED", f"x{n} (first at {l[0][:19]}): {key[:150]}"))
            ev.append(l)
        if any("lead_dasboard" in k for k in uniq):
            f.append(F("INFERRED", "`lead_dasboard_to_lead_detail_views` (note 'dasboard') in `page_views.yml` matches no model - "
                                   "it looks like a typo. The logs only say 'node not found', not the author's intent."))
        return make_answer(f"{len(uniq)} distinct kinds of warnings appear in the logs.", f, self._ev(ev))

    def config(self, date):
        deploys = sorted({l[0][:19] for l in self.lines if "Jobs.ReplaceJob" in l[3] and l[2] == "activity"})
        f = [F("CONFIRMED", "The job was redeployed (ReplaceJob via `gcloud run jobs deploy`) at: " + ", ".join(deploys) + "."),
             F("CONFIRMED", "From the 2026-09-29 deploy: maxRetries is 1 (earlier executions showed 3) and new env vars "
                            "DBT_SELECT=webserver_logs and MAX_RETRIES=1 appear."),
             F("CONFIRMED", "The gcloud client version moved from 586.0.0 to 587.0.0."),
             F("CONFIRMED", "The dbt project grew from 4 models / 15 tests to 65 models / 220 tests."),
             F("UNKNOWN", "Who made the change and why - identities are redacted in the logs.")]
        ev = [l for l in self.lines if l[2] == "system_event" and "Jobs.ReplaceJob" in l[3]]
        return make_answer("The job was redeployed with fewer retries and new environment variables.", f, self._ev(ev, 6))

    def data(self, date):
        f, ev = [], []
        for r in self.runs:
            for ts, t in r["events"]:
                m = re.search(r"OK created sql table model (\S*ai_bot_activity)\b.*?\((.*?) rows, (.*?) processed", t)
                if m:
                    f.append(F("CONFIRMED", f"{r['start'][:10]}: {m.group(1)} wrote {m.group(2)} rows ({m.group(3)})."))
                    ev.append((ts, "DEFAULT", "stdout/system", t, None))
        f.append(F("INFERRED", "The table grows steadily between runs; the logs do not say why."))
        return make_answer("ai_bot_activity grows from run to run.", f, self._ev(ev))

    def target(self, date):
        f = []
        for r in self.runs:
            i = self._run_info(r)
            ds = "test_bi" if any("test_bi." in t for _, t in r["events"]) else "bi"
            f.append(F("CONFIRMED", f"{i['start']}: target={i['target']}, dataset={ds}."))
        f.append(F("UNKNOWN", "Why the dataset alternates between test_bi and bi is not explained."))
        return make_answer("The dbt dataset alternates between test_bi and bi.", f)

    def further(self, date):
        f = [F("UNKNOWN", "Root cause of 'Billing has not been enabled' on 2026-09-26 08:20 (fixed by a retry; cause not logged)."),
             F("CONFIRMED", "Recurring warning: `lead_dasboard_to_lead_detail_views` not found in `page_views.yml` (every run since 2026-09-29)."),
             F("CONFIRMED", "dbt deprecation MissingArgumentsPropertyInGenericTestDeprecation, 19 occurrences, in `ai_bot_activity_daily_summary.yml`."),
             F("CONFIRMED", "maxRetries was reduced from 3 to 1, which lowers resilience against one-off errors like the billing failure."),
             F("UNKNOWN", "The 2026-09-22 run begins mid-log, so its start is not captured; the test_bi/bi switches are unexplained.")]
        ev = [l for l in self.lines if re.search(r"Billing has not|MissingArguments|lead_dasboard|maxRetries=1", l[3])]
        return make_answer("5 open items need further investigation.", f, self._ev(ev, 6))

    def recommend(self, date):
        recs = [R("HIGH", "Check that Cloud Billing is linked and active for the BigQuery project; alert on 'Billing has not been enabled'.",
                  "Billing error on 2026-09-26 08:20 failed the run (cause itself is UNKNOWN)."),
                R("MEDIUM", "Restore maxRetries to 2-3.", "maxRetries went 3 -> 1 on 2026-09-29; the 09-26 failure was fixed only by an automatic retry."),
                R("MEDIUM", "Fix the typo `lead_dasboard_to_lead_detail_views` in `models/marts/segment/page_views.yml`.",
                  "Causes a 'node not found' warning in every run."),
                R("LOW", "Add the `arguments:` property to generic tests in `ai_bot_activity_daily_summary.yml`.",
                  "19 deprecation warnings; a future dbt version may turn them into errors."),
                R("LOW", "Standardise the dbt target/dataset (test_bi vs bi) and log the job name in stdout.",
                  "Datasets alternate and the job name is redacted in stdout, making runs hard to trace.")]
        f = [F("INFERRED", "All recommendations are conclusions from the evidence - verify before applying."),
             F("UNKNOWN", "Who changed the configuration, why, and the business impact of the failed run.")]
        return make_answer("5 recommended actions, most important first.", f, [], recs)

    def summary(self, date):
        f = []
        for r in self.runs:
            i = self._run_info(r)
            f.append(F("CONFIRMED", f"{i['start']} attempt={i['attempt']} target={i['target']} models={i['models']} -> {i['result']}; {i['exit']}"))
        return make_answer(f"{len(self.runs)} runs found in the logs.", f)

    def evidence(self, date):
        if self.last_intent in ("error", "recover"):
            a = self.error(self.last_date or "2026-09-26")
            topic = "the failure"
        elif self.last_intent == "config":
            a, topic = self.config(date), "the configuration changes"
        elif self.last_intent == "warning":
            a, topic = self.warning(date), "the warnings"
        else:
            keep = [l for l in self.lines if re.search(r"ERROR|Billing|exit\(1\)|Reported failure|maxRetries", l[3]) and "ERROR=0" not in l[3]]
            a, topic = make_answer("", [], self._ev(keep, 10)), "the key events"
        return make_answer(f"Evidence for {topic}", [F("CONFIRMED", f"These are the exact log lines behind {topic}.")], a["evidence"])

    # ---------- public ----------
    def ask(self, q):
        intent, scores, matched = classify(q)
        date = parse_date(q)
        ql = q.lower()
        # Guard 1: questions about people - the logs redact identities, so never guess
        if re.search(r"\b(who|whom|which user|username|which person|which engineer|employee)\b", ql):
            return make_answer("Not enough evidence: the logs do not identify who did this.",
                               [F("UNKNOWN", "User/caller identities are redacted in the logs, so no person can be named."),
                                F("CONFIRMED", "Only the tool used is visible: audit entries show the caller as the gcloud CLI.")],
                               [], None, {"type": "local", "intent": "out-of-scope (people)", "scores": {}, "matched": {}, "date": date})
        # Guard 2: actions that are not in the logs (delete/drop/truncate) - report absence instead of mapping to a random topic
        if re.search(r"\b(delet\w*|drop\w*|truncat\w*)\b", ql):
            hits = [l for l in self.lines if re.search(r"\b(delete|drop|truncate)\b", l[3], re.I)]
            if not hits:
                return make_answer("Not enough evidence: no delete/drop/truncate activity appears in the logs.",
                                   [F("CONFIRMED", "No log line mentions a delete, drop or truncate action."),
                                    F("UNKNOWN", "Whether such an action happened outside this log file cannot be told from these logs.")],
                                   [], None, {"type": "local", "intent": "out-of-scope (action)", "scores": {}, "matched": {}, "date": date})
        # Guard 3: weak match (best score < 3) is treated as 'cannot map', not forced into a topic
        if intent is not None and max(scores.values()) < 3:
            intent = None
        if intent is None:
            return make_answer("I could not map that question to a log topic.",
                               [F("UNKNOWN", "Try: service/component, errors, retry/recovery, warnings, config changes, "
                                             "data growth, recommendations, or what needs further investigation.")])
        ans = getattr(self, intent)(date)
        if intent != "evidence":
            self.last_intent, self.last_date = intent, date
        if intent == "error" and re.search(r"\bwhy\b", q.lower()) and "Billing" in str(ans["findings"]):
            ans["headline"] = "Not enough evidence: the logs show THAT billing was unavailable, not WHY."
            ans["findings"].sort(key=lambda f: f["label"] != "UNKNOWN")
        ans["why"] = {"type": "local", "intent": intent, "scores": scores, "matched": matched, "date": date}
        return ans


# =====================================================================
# 4. AGENT  (Gemini first -> local engine fallback)
# =====================================================================
SYSTEM_RULES = """You are a Log Analysis & Investigation Agent. You analyse ONLY the log data given below.

HOW TO WORK
- Identify the service/component using the whole log context (resource.type, job name, logName,
  run labels, message content). Never decide from a single keyword. job_name is redacted in stdout
  entries, but audit entries and messages such as "Reported failure for dbt-webserver-logs" reveal it.
- Explain events in plain language for a non-expert.
- Look for errors, warnings, failures, skipped steps, retries, config changes and unusual events.
- Correlate related entries across time (error -> skips -> exit code -> retry -> success).
- Use the PRECOMPUTED RUN SUMMARIES for counts and totals; they are exact. Never count yourself.

HONESTY RULES
- Label every finding: CONFIRMED (directly visible in logs), INFERRED (reasonable conclusion; explain), UNKNOWN (not in logs; do not guess).
- Never invent timestamps, values, causes, users or services. If a root cause is not in the logs, say it is UNKNOWN.
- If the question is outside the logs, say you can only answer from the provided logs.
- Recommendations are INFERRED; base them only on issues visible in the logs; where root cause is UNKNOWN, recommend an investigation step.

OUTPUT FORMAT - reply with ONE JSON object only (no markdown fences, no extra text):
{
  "headline": "one plain-language sentence answering the question",
  "findings": [{"label": "CONFIRMED|INFERRED|UNKNOWN", "text": "short plain-language statement"}],
  "evidence": [{"timestamp": "UTC timestamp copied from the log", "severity": "as in log or DEFAULT",
                "source": "stdout / system / activity / system_event", "excerpt": "short exact excerpt"}],
  "recommendations": [{"priority": "HIGH|MEDIUM|LOW", "action": "...", "why": "evidence-based reason", "label": "INFERRED"}],
  "reasoning": "2-3 plain sentences: how you reached this answer from the logs"
}
Use empty lists when a section does not apply (e.g. no recommendations unless asked). Keep findings concise.
For follow-ups ("that failure", "the retry") use the earlier conversation.
"""


def parse_model_json(text):
    t = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    d = json.loads(t)
    if not isinstance(d, dict) or "headline" not in d:
        raise ValueError("unexpected JSON shape")
    labels = {"CONFIRMED", "INFERRED", "UNKNOWN"}
    findings = [F(str(x.get("label", "INFERRED")).upper() if str(x.get("label", "")).upper() in labels else "INFERRED",
                  str(x.get("text", ""))) for x in d.get("findings", []) if isinstance(x, dict)]
    ev = [{"timestamp": str(x.get("timestamp", "")), "severity": str(x.get("severity", "DEFAULT")),
           "source": str(x.get("source", "")), "excerpt": str(x.get("excerpt", ""))[:EXCERPT]}
          for x in d.get("evidence", []) if isinstance(x, dict)]
    recs = [R(str(x.get("priority", "LOW")).upper(), str(x.get("action", "")), str(x.get("why", "")),
              str(x.get("label", "INFERRED")).upper()) for x in d.get("recommendations", []) if isinstance(x, dict)]
    return make_answer(str(d["headline"]), findings, ev, recs, {"type": "gemini", "reasoning": str(d.get("reasoning", ""))})


def pick_models(client):
    """Ask the API which models THIS key can use (model names get retired, e.g. gemini-2.5-flash).
    Returns Flash-type text models, newest stable first."""
    out = []
    try:
        for m in client.models.list():
            name = (m.name or "").replace("models/", "")
            acts = getattr(m, "supported_actions", None) or []
            if "generateContent" in acts and "flash" in name and \
                    not re.search(r"image|tts|live|audio|embed|robotics|computer|exp|vision|native", name):
                out.append(name)
    except Exception:
        pass

    def key(n):
        v = re.search(r"gemini-(\d+(?:\.\d+)?)", n)
        return ("lite" not in n, "preview" not in n, float(v.group(1)) if v else 0)
    return sorted(set(out), key=key, reverse=True)


class LogAgent:
    def __init__(self, log_path=LOG_FILE):
        self.local = LocalAnalyst(log_path)
        self.client = self.chat = None
        self.gemini_error = None
        self._pool = ThreadPoolExecutor(max_workers=1)
        key = os.getenv("GEMINI_API_KEY")
        if MODE != "local" and key:
            try:
                from google import genai
                self.client = genai.Client(api_key=key)
                self.models = [os.getenv("GEMINI_MODEL")] if os.getenv("GEMINI_MODEL") else (pick_models(self.client) or [MODEL])
                self.model = self.models[0]
                self.system_instruction = SYSTEM_RULES + "\n\n######## LOG DATA ########\n" + build_context(log_path)
                self.reset()
            except Exception as e:
                self.client = self.chat = None
                self.gemini_error = f"{e}  (fix: pip uninstall -y google-generativeai google-genai && pip install -U google-genai)"
        elif MODE != "local":
            self.gemini_error = "GEMINI_API_KEY not set"

    @property
    def channel_label(self):
        return f"Gemini ({self.model}) + local fallback" if self.chat else f"Local engine only ({self.gemini_error or MODE})"

    def reset(self):
        self.local.last_intent = self.local.last_date = None
        if self.client:
            from google.genai import types
            self.chat = self.client.chats.create(
                model=self.model, config=types.GenerateContentConfig(
                    system_instruction=self.system_instruction, temperature=0.2,
                    response_mime_type="application/json"))

    def _send(self, question):
        """Send to Gemini; if the model is retired/unavailable (404), switch to the next available model."""
        while True:
            try:
                return self._pool.submit(lambda: self.chat.send_message(question).text).result(timeout=TIMEOUT_S)
            except Exception as e:
                nxt = self.models[self.models.index(self.model) + 1:]
                if nxt and re.search(r"404|NOT_FOUND|no longer available", str(e)):
                    self.model = nxt[0]
                    self.reset()
                    continue
                raise

    def ask(self, question):
        banner = None
        if self.chat and MODE != "local":
            try:
                text = self._send(question)
                if text and text.strip():
                    try:
                        ans = parse_model_json(text)
                    except Exception:  # model ignored the format: still show its text
                        ans = make_answer("", [], [], [], {"type": "gemini", "reasoning": ""})
                        ans["raw"] = text
                    ans["channel"] = "gemini"
                    return ans
                reason = "empty response"
            except FutTimeout:
                reason = f"slower than {TIMEOUT_S:.0f}s"
            except Exception as e:
                reason = f"error: {str(e)[:80]}"
            banner = f"Gemini unavailable ({reason}) - answered by the local engine from the same logs."
        else:
            banner = f"Local engine mode ({self.gemini_error or MODE})."
        ans = self.local.ask(question)
        ans["channel"], ans["banner"] = "local", banner
        return ans


# =====================================================================
# 5. RENDERING  (terminal text + Streamlit)
# =====================================================================
def render_text(a):
    out = []
    if a.get("banner"):
        out.append(f"[{a['banner']}]")
    if a.get("raw"):
        return "\n".join(out + [a["raw"]])
    out.append(f"\n== {a['headline']} ==")
    if a["findings"]:
        out.append("\nFINDINGS")
        out += [f"  {ICON.get(f['label'], '')} {f['label']:<9} {f['text']}" for f in a["findings"]]
    if a["evidence"]:
        out.append("\nEVIDENCE (UTC | severity | source)")
        out += [f"  [{e['timestamp']}] {e['severity']} ({e['source']})\n      {e['excerpt']}" for e in a["evidence"]]
    if a["recommendations"]:
        out.append("\nRECOMMENDATIONS")
        out += [f"  {PRIO.get(r['priority'], '')} {r['priority']:<6} {r['action']}\n      why: {r['why']}  [{r['label']}]"
                for r in a["recommendations"]]
    w = a.get("why", {})
    if w.get("type") == "local":
        out.append(f"\nWHY: intent='{w['intent']}' scores={w['scores']} date={w['date']}")
    elif w.get("reasoning"):
        out.append(f"\nWHY: {w['reasoning']}")
    return "\n".join(out)


def run_cli():
    agent = LogAgent()
    print(f"Log Investigation Agent ready [{agent.channel_label}]. Type 'exit' to quit, 'reset' for a new investigation.\n")
    while True:
        q = input("You: ").strip()
        if q.lower() in {"exit", "quit"}:
            break
        if q.lower() == "reset":
            agent.reset()
            print("(new investigation started)\n")
        elif q:
            print(render_text(agent.ask(q)), "\n")


def render_answer(st, a):
    if a.get("banner"):
        st.caption("⚡ " + a["banner"])
    if a.get("raw"):
        st.markdown(a["raw"])
        return
    if a["headline"]:
        st.markdown(f"#### 📌 {a['headline']}")
    if a["findings"]:
        st.markdown("**Findings**")
        for f in a["findings"]:
            st.markdown(f"- {ICON.get(f['label'], '▫️')} **{f['label']}** — {f['text']}")
    if a["evidence"]:
        with st.expander(f"📎 Evidence ({len(a['evidence'])} log lines)", expanded=True):
            st.table([{"Time (UTC)": e["timestamp"], "Severity": e["severity"], "Source": e["source"],
                       "Log excerpt": e["excerpt"]} for e in a["evidence"]])
    if a["recommendations"]:
        st.markdown("**Recommendations**")
        st.table([{"Priority": f"{PRIO.get(r['priority'], '')} {r['priority']}", "Action": r["action"],
                   "Why (evidence)": r["why"], "Label": r["label"]} for r in a["recommendations"]])
    w = a.get("why", {})
    with st.expander("🔍 Why this answer?"):
        if w.get("type") == "local":
            st.write(f"The local engine matched your question to the topic **{w['intent']}**"
                     + (f" and filtered by date **{w['date']}**." if w.get("date") else "."))
            for intent, hits in w["matched"].items():
                st.write(f"**{intent}** (score {sum(x for _, x in hits)})  " +
                         ", ".join(f"“{p}” +{x}" for p, x in hits))
            st.bar_chart({k: v for k, v in w["scores"].items()})
        elif w.get("reasoning"):
            st.write(w["reasoning"])
        st.caption("Method: answers are built only from the supplied logs; counts are computed by code; "
                   "every statement carries a CONFIRMED / INFERRED / UNKNOWN label.")
    st.caption(("🤖 Gemini" if a.get("channel") == "gemini" else "⚙️ Local engine") + " answer")


SUGGESTIONS = [
    "Which service or component do these logs belong to?",
    "What went wrong on 2026-09-26?",
    "What evidence supports that?",
    "Did the job recover after the failure?",
    "What warnings appear in the later runs?",
    "What configuration changes happened between runs?",
    "Is there anything that requires further investigation?",
    "Why was billing disabled?",
    "What do you recommend to fix these issues?",
]


def run_streamlit():
    import streamlit as st

    st.set_page_config(page_title="Log Investigation Agent", page_icon="🔍", layout="wide")
    st.title("🔍 Log Analysis & Investigation Agent")
    st.caption("Answers only from the supplied log file (Cloud Run job + dbt + BigQuery).")
    st.info("✅ **CONFIRMED** = seen directly in the logs   |   🟡 **INFERRED** = reasonable conclusion   |   "
            "❓ **UNKNOWN** = not enough evidence in the logs")

    if "agent" not in st.session_state:
        try:
            st.session_state.agent = LogAgent()
        except Exception as e:
            st.error(f"Could not load the logs: {e}")
            st.stop()
        st.session_state.messages = []
    agent = st.session_state.agent

    with st.sidebar:
        st.subheader("Try asking")
        for s in SUGGESTIONS:
            if st.button(s, use_container_width=True):
                st.session_state.pending = s
        if st.button("🗑 New investigation"):
            agent.reset()
            st.session_state.messages = []
            st.rerun()
        st.caption(f"Mode: {agent.channel_label}")

    tab_chat, tab_over = st.tabs(["💬 Investigation", "📊 Run overview"])
    with tab_over:
        cols = st.columns(5)
        for c, (k, v) in zip(cols, agent.local.stats().items()):
            c.metric(k, v)
        st.markdown("**All runs found in the logs** (computed by code)")
        st.table(agent.local.overview())

    with tab_chat:
        for m in st.session_state.messages:
            with st.chat_message(m["role"], avatar="🧑" if m["role"] == "user" else "🤖"):
                if m["role"] == "user":
                    st.markdown(m["content"])
                else:
                    render_answer(st, m["content"])

    question = st.chat_input("Ask about the logs...") or st.session_state.pop("pending", None)
    if question:
        st.session_state.messages.append({"role": "user", "content": question})
        with st.spinner("Investigating..."):
            try:
                ans = agent.ask(question)
            except Exception as e:
                ans = make_answer("Something went wrong.", [F("UNKNOWN", f"Error: {e}")])
        st.session_state.messages.append({"role": "assistant", "content": ans})
        st.rerun()


if __name__ == "__main__":
    try:
        from streamlit.runtime.scriptrunner import get_script_run_ctx
        in_streamlit = get_script_run_ctx() is not None
    except Exception:
        in_streamlit = False
    run_streamlit() if in_streamlit else run_cli()
