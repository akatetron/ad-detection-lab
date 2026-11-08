"""Minimal Sigma evaluator for offline rule testing.

Supports the subset of Sigma used in this repo: field maps, value lists (OR),
modifiers contains / startswith / endswith / all / re, and conditions built from
selection names, and / or / not, parentheses, "1 of x*" and "all of x*".
Matching is case-insensitive, as in the Sigma spec.
"""
import fnmatch
import json
import re
from pathlib import Path

import yaml


def load_rule(path):
    with open(path, encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_events(path):
    p = Path(path)
    if not p.exists():
        return []
    return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line.strip()]


def _match_value(actual, expected, mods):
    if actual is None:
        return False
    a, e = str(actual).lower(), str(expected).lower()
    if "re" in mods:
        return re.search(str(expected), str(actual), re.IGNORECASE) is not None
    if "contains" in mods:
        return e in a
    if "startswith" in mods:
        return a.startswith(e)
    if "endswith" in mods:
        return a.endswith(e)
    return a == e


def _match_field(event, key, values):
    field, *mods = key.split("|")
    values = values if isinstance(values, list) else [values]
    test = all if "all" in mods else any
    return test(_match_value(event.get(field), v, mods) for v in values)


def _match_selection(event, sel):
    if isinstance(sel, list):  # list of maps = OR
        return any(_match_selection(event, s) for s in sel)
    return all(_match_field(event, k, v) for k, v in sel.items())


def _expand(condition, names):
    def repl(m):
        quant, pattern = m.group(1), m.group(2)
        hits = [n for n in names if fnmatch.fnmatch(n, pattern)] or ["False"]
        joiner = " or " if quant == "1" else " and "
        return "(" + joiner.join(hits) + ")"
    return re.sub(r"\b(1|all) of (\w+\*?)", repl, condition)


def matches(rule, event, disable_filters=False):
    det = {k: v for k, v in rule["detection"].items() if k != "condition"}
    results = {}
    for name, sel in det.items():
        if disable_filters and name.startswith("filter"):
            results[name] = False
        else:
            results[name] = _match_selection(event, sel)
    expr = _expand(rule["detection"]["condition"], list(det))
    for name in sorted(results, key=len, reverse=True):
        expr = re.sub(rf"\b{re.escape(name)}\b", str(results[name]), expr)
    if not re.fullmatch(r"[\sA-Za-z()]*", expr) or set(re.findall(r"[A-Za-z]+", expr)) - {"True", "False", "and", "or", "not"}:
        raise ValueError(f"Unsupported condition: {rule['detection']['condition']}")
    return eval(expr, {"__builtins__": {}}, {})
