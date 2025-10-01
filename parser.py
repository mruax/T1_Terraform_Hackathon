import json
import re
import uuid
from datetime import datetime

ISO_RE = re.compile(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?')
LEVEL_RE = re.compile(r'\b(ERROR|WARN|WARNING|INFO|DEBUG|TRACE|FATAL)\b', re.I)

# секции
PLAN_START = re.compile(r"(terraform plan|Terraform will perform the following actions)", re.I)
PLAN_END = re.compile(r"Plan: \d+ to add, \d+ to change, \d+ to destroy", re.I)
APPLY_START = re.compile(r"(terraform apply|Applying changes)", re.I)
APPLY_END = re.compile(r"Apply complete", re.I)


def extract_timestamp(s):
    m = ISO_RE.search(s)
    if m:
        return m.group(0)
    return datetime.utcnow().isoformat()


def extract_level(s):
    m = LEVEL_RE.search(s)
    if m:
        return m.group(1).upper()
    return "INFO"


def parse_line(line: str, section_state: dict):
    line = line.strip()
    if not line:
        return None

    # Пробуем JSON
    obj = None
    try:
        obj = json.loads(line)
    except json.JSONDecodeError:
        pass

    entry = {
        "id": str(uuid.uuid4()),
        "timestamp": None,
        "level": None,
        "message": None,
        "raw": line,
        "section_type": section_state.get("type"),
        "section_id": section_state.get("id"),
        "http_req_preview": None,
        "http_res_preview": None,
        "lazy_json": {}
    }

    if obj:
        entry["timestamp"] = obj.get("@timestamp") or extract_timestamp(line)
        entry["level"] = obj.get("@level", "INFO").upper()
        entry["message"] = obj.get("@message", "")

        # JSON body извлекаем "лениво"
        if "tf_http_req_body" in obj:
            body = obj["tf_http_req_body"]
            entry["http_req_preview"] = str(body)[:200]  # первые 200 символов
            entry["lazy_json"]["req"] = body

        if "tf_http_res_body" in obj:
            body = obj["tf_http_res_body"]
            entry["http_res_preview"] = str(body)[:200]
            entry["lazy_json"]["res"] = body

    else:
        entry["timestamp"] = extract_timestamp(line)
        entry["level"] = extract_level(line)
        entry["message"] = line

    # Обновляем state для секций
    msg = entry["message"]
    if msg:
        if PLAN_START.search(msg):
            section_state["type"] = "plan"
            section_state["id"] = str(uuid.uuid4())
            entry["section_type"] = section_state["type"]
            entry["section_id"] = section_state["id"]
            entry["section_marker"] = "start"

        elif PLAN_END.search(msg) and section_state.get("type") == "plan":
            entry["section_type"] = section_state["type"]
            entry["section_id"] = section_state["id"]
            entry["section_marker"] = "end"
            section_state.clear()

        elif APPLY_START.search(msg):
            section_state["type"] = "apply"
            section_state["id"] = str(uuid.uuid4())
            entry["section_type"] = section_state["type"]
            entry["section_id"] = section_state["id"]
            entry["section_marker"] = "start"

        elif APPLY_END.search(msg) and section_state.get("type") == "apply":
            entry["section_type"] = section_state["type"]
            entry["section_id"] = section_state["id"]
            entry["section_marker"] = "end"
            section_state.clear()

    return entry


def parse_log_file(path: str):
    section_state = {}
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            entry = parse_line(line, section_state)
            if entry:
                yield entry


if __name__ == "__main__":
    for e in parse_log_file("src/1. plan_test-k801vip_tflog.json"):
        if e["section_type"]:
            print(json.dumps(e, ensure_ascii=False, indent=2))
