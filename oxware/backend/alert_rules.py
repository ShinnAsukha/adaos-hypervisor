"""OXware Alert Rules — threshold-based alerting"""
import json, os, uuid, logging, threading
from pathlib import Path
from datetime import datetime

log = logging.getLogger("alert_rules")
_RULES_FILE   = "/var/lib/oxware/alert_rules.json"
_HISTORY_FILE = "/var/log/oxware/alert_history.jsonl"
_lock = threading.Lock()

METRICS   = ["cpu_pct", "mem_pct", "disk_pct"]
OPERATORS = ["gt", "lt", "gte", "lte"]
ACTIONS   = ["log", "webhook", "email"]

def _load():
    try:
        p = Path(_RULES_FILE)
        if p.exists(): return json.loads(p.read_text())
    except Exception: pass
    return []

def _save(rules):
    Path(_RULES_FILE).parent.mkdir(parents=True, exist_ok=True)
    Path(_RULES_FILE).write_text(json.dumps(rules, indent=2))

def _append_history(entry):
    try:
        Path(_HISTORY_FILE).parent.mkdir(parents=True, exist_ok=True)
        with open(_HISTORY_FILE, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception: pass

def list_rules():
    with _lock: return _load()

def create_rule(name, metric, operator, threshold, scope="host",
                vm_id=None, action="log", action_config=None, cooldown_minutes=15):
    if metric not in METRICS: raise ValueError(f"Invalid metric: {metric}")
    if operator not in OPERATORS: raise ValueError(f"Invalid operator: {operator}")
    rule = {"id": str(uuid.uuid4())[:8], "name": str(name)[:100],
            "metric": metric, "operator": operator,
            "threshold": float(threshold), "scope": scope,
            "vm_id": vm_id, "action": action,
            "action_config": action_config or {},
            "cooldown_minutes": int(cooldown_minutes),
            "last_triggered": None, "enabled": True,
            "created_at": datetime.now().isoformat()}
    with _lock:
        rules = _load(); rules.append(rule); _save(rules)
    return rule

def update_rule(rule_id, **kwargs):
    with _lock:
        rules = _load()
        for r in rules:
            if r["id"] == rule_id:
                for k, v in kwargs.items():
                    if k in r: r[k] = v
                break
        _save(rules)

def delete_rule(rule_id):
    with _lock:
        rules = [r for r in _load() if r["id"] != rule_id]
        _save(rules)

def _eval(current, operator, threshold):
    ops = {"gt": lambda a,b: a>b, "lt": lambda a,b: a<b,
           "gte": lambda a,b: a>=b, "lte": lambda a,b: a<=b}
    return ops.get(operator, lambda a,b: False)(current, threshold)

def _trigger(rule, value):
    try:
        entry = {"rule_id": rule["id"], "name": rule["name"],
                 "metric": rule["metric"], "value": value,
                 "threshold": rule["threshold"], "at": datetime.now().isoformat()}
        _append_history(entry)
        log.warning("ALERT: %s — %s=%.1f %s %.1f",
                    rule["name"], rule["metric"], value, rule["operator"], rule["threshold"])
        if rule["action"] == "webhook":
            url = (rule.get("action_config") or {}).get("url")
            if url:
                import requests, threading
                threading.Thread(target=lambda: requests.post(url, json=entry, timeout=10),
                                 daemon=True).start()
    except Exception as e:
        log.error("Alert trigger error: %s", e)

def check_rules(metrics: dict):
    triggered = []
    now = datetime.now()
    with _lock: rules = list(_load())
    changed = False
    for rule in rules:
        if not rule.get("enabled"): continue
        val = metrics.get(rule["metric"])
        if val is None: continue
        if not _eval(float(val), rule["operator"], rule["threshold"]): continue
        last = rule.get("last_triggered")
        if last:
            from datetime import timedelta
            diff = (now - datetime.fromisoformat(last)).total_seconds() / 60
            if diff < rule.get("cooldown_minutes", 15): continue
        rule["last_triggered"] = now.isoformat()
        changed = True
        _trigger(rule, float(val))
        triggered.append(rule["id"])
    if changed:
        with _lock:
            all_rules = _load()
            lu = {r["id"]: r for r in rules}
            for r in all_rules:
                if r["id"] in lu: r["last_triggered"] = lu[r["id"]]["last_triggered"]
            _save(all_rules)
    return triggered

def get_history(n=50):
    try:
        lines = Path(_HISTORY_FILE).read_text().splitlines()[-n:]
        return [json.loads(l) for l in lines if l.strip()]
    except Exception: return []
