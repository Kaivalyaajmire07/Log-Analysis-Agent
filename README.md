#  Log Analysis & Investigation Agent

An AI chatbot that investigates a Google Cloud Run + dbt + BigQuery log file (`logs.json`).
It answers **only from the supplied logs**, cites evidence for every finding, and labels each statement:

- ✅ **CONFIRMED** – seen directly in the logs
- 🟡 **INFERRED** – a reasonable conclusion from the evidence
- ❓ **UNKNOWN** – not enough evidence in the logs (the agent says so instead of guessing)

## What it can do
- Identify the service/component (Cloud Run job `dbt-webserver-logs`, dbt 1.12.4 + BigQuery)
- Explain events in plain language, find errors, warnings, skipped steps, retries and config changes
- Correlate entries over time (error → skipped steps → exit code → retry → success)
- Cite evidence: timestamp (UTC), severity, source, log excerpt
- Handle follow-up questions ("What evidence supports that?")
- Give prioritised recommendations (HIGH / MEDIUM / LOW, labelled INFERRED)

## Architecture
```
logs.json -> parser (clean + run summaries computed in code)
          -> Gemini (primary, long-context prompt)  --fails/slow-->  Local NLQ engine (fallback, no LLM)
          -> Streamlit chat UI  (or terminal chat)
```
- **Prompt-based long-context approach** – the cleaned log (~30k tokens) is placed in the Gemini system instruction. No LangChain, no vector DB/RAG, so related events are never split apart.
- **Exact numbers from code** – PASS/ERROR/SKIP counts and run summaries are computed in Python, not by the LLM.
- **Dual channel** – if Gemini has no key, errors, hits quota or is slower than `GEMINI_TIMEOUT_S`, a rule-based local engine answers from the same logs and the UI shows a "Gemini unavailable" banner.
- **Automatic model selection** – the app asks the API which Flash models the key can use (model names get retired) and switches model on a 404.
- **Same answer layout for both channels** – headline, findings with labels, evidence table, recommendations, "Why this answer?".

## Run it
```bash
pip install -r requirements.txt
```
1. Get a free key at https://aistudio.google.com/apikey
2. Copy `.env.example` to `.env` and put your key in it (never commit `.env`)
3. Keep `logs.json` next to `main.py`
```bash
python -m streamlit run main.py     # web chat at http://localhost:8501
python main.py                      # terminal chat
python list_models.py               # optional: list models your key can use
```

### Settings (`.env`)
| Variable | Meaning | Default |
|---|---|---|
| `GEMINI_API_KEY` | your Gemini key | – |
| `GEMINI_MODEL` | force a model (otherwise auto-selected) | auto |
| `GEMINI_TIMEOUT_S` | seconds to wait for Gemini before falling back | 25 (use 90) |
| `AGENT_MODE` | `hybrid`, `gemini` or `local` | hybrid |
| `LOG_FILE` | log file path | logs.json |

## Demo questions
1. Which service or component do these logs belong to?
2. What went wrong on 2026-09-26?
3. What evidence supports that? *(follow-up)*
4. Did the job recover after the failure?
5. What warnings appear in the later runs?
6. What configuration changes happened between runs?
7. Is there anything that requires further investigation?
8. Why was billing disabled? *(expected: UNKNOWN – not in the logs)*
9. What do you recommend to fix these issues?

## Key findings in the sample log
- 26 Sep 08:20 – run failed on `ai_bot_activity` ("Billing has not been enabled… sandbox mode"), 9 steps skipped, exit code 1; the retry at 08:22 passed 19/19. Why billing was unavailable is **UNKNOWN**.
- 29 Sep redeploy – `maxRetries` 3 → 1, new env vars `DBT_SELECT`, `MAX_RETRIES`; project grew from 4 to 65 models.
- Warnings – 19 `MissingArgumentsPropertyInGenericTestDeprecation`; typo `lead_dasboard_to_lead_detail_views` in `page_views.yml`.

## Honesty rules
Never invent timestamps, values, causes or users; say "not enough evidence" when the logs don't show it; refuse questions outside the logs.

## Files
`main.py` (all code) · `logs.json` · `requirements.txt` · `.env.example` · `list_models.py` · `.gitignore`

## Screenshots
Add your chat screenshots here.
<img width="1917" height="911" alt="image" src="https://github.com/user-attachments/assets/9f443bd2-8dec-4a0d-bd99-97c9e8a3646a" />
<img width="1425" height="827" alt="image" src="https://github.com/user-attachments/assets/a4f2d8fc-d5cd-478a-bb00-520c5b3438c3" />
<img width="1322" height="332" alt="image" src="https://github.com/user-attachments/assets/9691c326-c0f4-4b2f-94c6-a6fe5a7abc13" />
<img width="1447" height="842" alt="image" src="https://github.com/user-attachments/assets/fa1ee878-5070-48f6-bb78-746eed7332ef" />



