
import re
import json
import os
import datetime

from nemoguardrails.actions import action

PATTERNS = {
    "Indirect Prompt Injection": [
        r"ignore.{0,30}(previous|prior|above|document)",
        r"reveal.{0,30}(credential|token)",
        r"include.{0,30}hidden token",
        r"print.{0,30}internal identity"
    ],
    "Agent Identity Spoofing": [
        r"FROM:\\s*TRUSTED_ORCHESTRATOR",
        r"administrator mode",
        r"privileged operation",
        r"trusted orchestrator"
    ],
    "System Prompt Extraction": [
        r"system prompt",
        r"initial instructions",
        r"confidential.{0,30}instructions",
        r"repeat everything.{0,30}told"
    ],
    "RAG Poisoning": [
        r"grant.{0,30}access",
        r"poisoned.{0,30}document",
        r"follow this document.{0,30}instructions"
    ],
    "MCP Tool Abuse": [
        r"grant_demo_access",
        r"call.{0,30}tool",
        r"without additional authorization",
        r"execute.{0,30}privileged"
    ]
}

LOG_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    "attack_results",
    "guardrail_decisions.jsonl"
)

@action(name="CheckProject4InputAction")
async def check_project4_input(text: str):

    matched_category = None

    for category, patterns in PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE | re.DOTALL):
                matched_category = category
                break

        if matched_category:
            break

    allowed = matched_category is None

    record = {
        "timestamp": datetime.datetime.now().astimezone().isoformat(),
        "identity": "demo-user",
        "event_type": "INPUT_GUARDRAIL_CHECK",
        "category": matched_category or "None",
        "status": "PASSED" if allowed else "BLOCKED",
        "reason": (
            "No configured attack pattern detected."
            if allowed
            else "Suspicious instruction pattern detected."
        )
    }

    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    with open(LOG_PATH, "a", encoding="utf-8") as file:
        file.write(json.dumps(record) + "\\n")

    return allowed
