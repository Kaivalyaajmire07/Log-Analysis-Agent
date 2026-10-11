"""Run:  python list_models.py   -> prints the Gemini models your key can use (put one in .env as GEMINI_MODEL=...)"""
import os
from dotenv import load_dotenv
from google import genai
load_dotenv()
c = genai.Client(api_key=os.environ["GEMINI_API_KEY"])
for m in c.models.list():
    if "generateContent" in (m.supported_actions or []):
        print(m.name.replace("models/", ""))
