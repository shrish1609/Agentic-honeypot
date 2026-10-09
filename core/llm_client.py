"""
core/llm_client.py — Unified LLM client.

Primary:  Google Gemini 1.5 Flash (via new `google-genai` SDK)
Fallback: Groq openai/gpt-oss-20b (via raw REST, no extra SDK)

Bug fixes from v1:
- Switched from deprecated `google-generativeai` to `google-genai`
- Added proper timeout to Groq REST call
- parse_json_response now handles edge cases (empty string, non-dict JSON)
"""

import os
import json
import time
import logging

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)


class LLMClient:
    """
    Unified LLM client with automatic Groq fallback.

    Usage:
        client = LLMClient()
        text, model_name = client.chat(system_prompt, user_message)
        data = client.chat_json(system_prompt, user_message)  # returns parsed dict
    """

    def __init__(self):
        self._gemini_client = None
        self._setup_gemini()
        self._setup_groq()

    # ── Setup ────────────────────────────────────────────────────────────────

    def _setup_gemini(self):
        api_key = os.getenv("GEMINI_API_KEY")
        if not api_key:
            logger.warning("GEMINI_API_KEY not set — Gemini disabled.")
            return
        try:
            from google import genai
            from google.genai import types

            self._gemini_client = genai.Client(api_key=api_key)
            self._gemini_config = types.GenerateContentConfig(
                temperature=0.7,
                max_output_tokens=512,
            )
            # Some accounts no longer permit the older flash-lite alias, so keep
            # the model configurable and default to the working 2.5 Flash option.
            self._gemini_model = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
            logger.info(f"Gemini client initialized (google-genai SDK, model={self._gemini_model}).")
        except ImportError:
            logger.error("google-genai package not installed. Run: pip install google-genai")
        except Exception as e:
            logger.error(f"Gemini setup failed: {e}")

    def _setup_groq(self):
        self._groq_api_key = os.getenv("GROQ_API_KEY")
        # llama3-8b-8192 was decommissioned (May 2025); its replacement
        # llama-3.1-8b-instant was ALSO deprecated (Jun 17, 2026).
        # Current recommended free-tier model:
        self._groq_model = "openai/gpt-oss-20b"
        if self._groq_api_key:
            logger.info("Groq fallback client ready.")
        else:
            logger.warning("GROQ_API_KEY not set — Groq fallback disabled.")

    # ── Public API ───────────────────────────────────────────────────────────

    def chat(
        self,
        system_prompt: str,
        user_message: str,
    ) -> tuple[str, str]:
        """
        Returns (response_text, model_name_used).
        Tries Gemini first, falls back to Groq on any error.
        Raises RuntimeError if both providers fail.
        """
        # --- Gemini ---
        if self._gemini_client:
            try:
                from google.genai import types
                response = self._gemini_client.models.generate_content(
                    model=self._gemini_model,
                    contents=f"SYSTEM: {system_prompt}\n\nUSER: {user_message}",
                    config=self._gemini_config,
                )
                return response.text.strip(), self._gemini_model
            except Exception as e:
                logger.warning(f"Gemini call failed ({type(e).__name__}: {e}). Falling back to Groq.")

        # --- Groq fallback (with retry on 429) ---
        if self._groq_api_key:
            try:
                text = self._with_retry(
                    lambda: self._groq_chat(system_prompt, user_message)
                )
                return text, self._groq_model
            except Exception as e:
                logger.error(f"Groq also failed: {type(e).__name__}: {e}")

        raise RuntimeError(
            "All LLM providers failed. "
            "Check GEMINI_API_KEY and GROQ_API_KEY in your .env file."
        )

    def chat_json(
        self,
        system_prompt: str,
        user_message: str,
    ) -> tuple[dict, str]:
        """
        Convenience wrapper: calls chat() with JSON instruction injected,
        then parses and returns (parsed_dict, model_name).
        Returns ({}, model_name) on parse failure — never raises for bad JSON.
        """
        json_system = (
            system_prompt
            + "\n\nCRITICAL: Respond ONLY with valid JSON. "
            "No markdown fences, no backticks, no preamble text."
        )
        raw, model = self.chat(json_system, user_message)
        data = self._parse_json(raw)
        return data, model

    # ── Internals ────────────────────────────────────────────────────────────

    def _with_retry(self, fn, max_attempts: int = 3, base_delay: float = 2.0):
        """
        Call fn() with exponential backoff on rate-limit (429) errors.
        Used to handle Groq free-tier throttling during peak demo load.
        Raises the last exception if all attempts fail.
        """
        import requests as req_lib
        last_exc = None
        for attempt in range(max_attempts):
            try:
                return fn()
            except req_lib.exceptions.HTTPError as e:
                if e.response is not None and e.response.status_code == 429:
                    wait = base_delay * (2 ** attempt)   # 2s, 4s, 8s
                    logger.warning(
                        f"Rate limited (429). Waiting {wait:.0f}s before retry "
                        f"(attempt {attempt + 1}/{max_attempts})"
                    )
                    time.sleep(wait)
                    last_exc = e
                else:
                    raise  # non-429 HTTP errors are not retried
            except Exception as e:
                raise  # non-HTTP errors bubble up immediately
        raise last_exc  # all retries exhausted

    def _groq_chat(self, system_prompt: str, user_message: str) -> str:
        import requests

        resp = requests.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {self._groq_api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": self._groq_model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_message},
                ],
                "max_tokens": 512,
                "temperature": 0.7,
            },
            timeout=30,
        )
        resp.raise_for_status()
        return resp.json()["choices"][0]["message"]["content"].strip()

    @staticmethod
    def _parse_json(text: str) -> dict:
        """
        Robustly parse JSON from LLM output.
        Handles: markdown fences, leading/trailing whitespace, partial responses.
        Returns {} on any failure — callers must handle empty dict gracefully.
        """
        if not text or not text.strip():
            logger.warning("Empty LLM response for JSON parse.")
            return {}

        cleaned = text.strip()

        # Strip ```json ... ``` or ``` ... ``` wrappers
        if cleaned.startswith("```"):
            lines = cleaned.split("\n")
            # Remove first line (```json or ```) and last line (```)
            inner = lines[1:-1] if lines[-1].strip() == "```" else lines[1:]
            cleaned = "\n".join(inner).strip()

        try:
            parsed = json.loads(cleaned)
            if not isinstance(parsed, dict):
                logger.warning(f"JSON parsed but not a dict: {type(parsed)}")
                return {}
            return parsed
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode failed: {e}. Raw text (first 300 chars): {text[:300]}")
            return {}


# Module-level singleton — all nodes import this
llm = LLMClient()