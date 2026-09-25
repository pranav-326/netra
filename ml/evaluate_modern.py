"""Test the shipped models on phishing written ~20 years after their training data.

Both learned models were trained on 2004–2007 phishing and 2002 benign mail. This
scores 2024–2025 phishing from the same collector (Jose Nazario's corpus) with the
production artifacts and the production scorer, never training on it. If recall
holds up, the models learned phishing rather than the era; if it collapses, that is
the answer.

It measures missed phishing only. There is no modern legitimate mail here, so it says
nothing about false positives.

Data: Jose Nazario, phishing corpus, https://monkey.org/~jose/phishing/, CC-BY-4.0.

Usage:
    python -m ml.evaluate_modern
"""

import hashlib
import mailbox
import os
import re
import sys
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from ml.corpus import _build_parser, analyze_raw_email  # noqa: E402
from ml.train_text_model import deduplicate, load_cache  # noqa: E402
from services.threat_engine.src import text_features  # noqa: E402
from services.threat_engine.src.ml_scorer import MLScorer  # noqa: E402
from services.threat_engine.src.scorer import (  # noqa: E402
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    apply_ml_contribution,
    apply_text_contribution,
    evaluate_threat_score,
    finalize_score,
)
from services.threat_engine.src.text_scorer import TextScorer  # noqa: E402

DATA = os.path.join(REPO_ROOT, "data")
YEARS = (2024, 2025)
REPORT_PATH = os.path.join(REPO_ROOT, "ml", "reports", "modern_phishing_evaluation.md")

# Out-of-sample results on 2007 phishing (grouped split, ml/train_text_model.py),
# the fair in-era reference for "did recall hold up".
IN_ERA = {
    "Rules + LR": (0.2517, 0.6051),
    "Rules + LR + text": (0.3881, 0.7477),
}

# Rules + LR + text on the same deduplicated emails, measured before the modern-lure
# rules existed: (MALICIOUS, SUSPICIOUS+) per year.
BEFORE_MODERN_RULES = {2024: (0.185, 0.395), 2025: (0.253, 0.551)}

# The modern-lure rules were designed by reading 2024 only; 2025 is the held-out test.
DESIGN_YEAR, HELD_OUT_YEAR = 2024, 2025
MODERN_RULES = {"HDR-BRAND-SPOOF", "ATT-HTML", "URL-ABUSED-HOST", "CNT-LURE-CALLBACK", "CNT-LURE-MAILBOX",
                "CNT-LURE-DOCUMENT", "CNT-LURE-DELIVERY", "CNT-LURE-RENEWAL", "CNT-LURE-CRYPTO"}


def _near_key(subject, plain, html):
    words = re.findall(r"[a-z]{2,}", text_features.clean_text(subject, plain, html))
    return hashlib.sha1(" ".join(words).encode()).hexdigest() if len(words) >= 20 else None


def _exact_key(subject, plain, html):
    body = " ".join(((subject or "") + " " + (plain or html or "")).split())
    return hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest()


def main() -> int:
    parser = _build_parser()
    lr, text = MLScorer(), TextScorer()
    if not (lr.available and text.available):
        print(f"Shipped models not loadable: LR={lr.unavailable_reason} TEXT={text.unavailable_reason}")
        return 1

    training, _ = deduplicate(load_cache())
    train_exact = {_exact_key(r["subject"], r["body_plain"], r["body_html"]) for r in training}
    train_near = {_near_key(r["subject"], r["body_plain"], r["body_html"]) for r in training} - {None}
    train_vocab_hits = Counter()

    rows, dropped = [], Counter()
    seen_exact, seen_near = set(), set()
    for year in YEARS:
        for message in mailbox.mbox(os.path.join(DATA, f"phishing-{year}")):
            try:
                analyzed = analyze_raw_email(parser, message.as_bytes(), str(uuid.uuid4()), resolver=None)
            except Exception:
                dropped["unparseable"] += 1
                continue
            p = analyzed.parsed_email
            exact = _exact_key(p.headers.subject, p.body_plain, p.body_html)
            near = _near_key(p.headers.subject, p.body_plain, p.body_html)
            if exact in train_exact or (near and near in train_near):
                dropped["duplicate_of_training"] += 1
                continue
            if exact in seen_exact or (near and near in seen_near):
                dropped["duplicate_within_modern"] += 1
                continue
            seen_exact.add(exact)
            if near:
                seen_near.add(near)

            _, _, _, rules, _ = evaluate_threat_score(analyzed.analysis)
            lr_pred = lr.predict(analyzed)
            text_pred = text.predict(p)
            with_lr = apply_ml_contribution(list(rules), lr_pred)
            with_text = apply_text_contribution(with_lr, text_pred)

            tokens = text_features.tokenize(text_features.clean_text(p.headers.subject, p.body_plain, p.body_html))
            known = sum(1 for t in tokens if t in text.terms)
            has_authres = any(k.lower() == "authentication-results" for k in (p.headers.raw_headers or {}))

            rows.append({
                "year": year,
                "rules": finalize_score(rules)[3],
                "rules_lr": finalize_score(with_lr)[3],
                "rules_lr_text": finalize_score(with_text)[3],
                "fired": [c.rule_id for c in rules],
                "lr_flag": lr_pred.is_phishing,
                "text_flag": text_pred.probability >= text_pred.threshold,
                "text_points": text_pred.points,
                "top_terms": text_pred.top_terms(3),
                "oov": 1 - known / len(tokens) if tokens else 1.0,
                "empty_text": not tokens,
                "authres": has_authres,
                "spf": analyzed.analysis.header_analysis.spf_verdict,
            })

    write_report(rows, dropped)
    return 0


def recall(rows, key, cut):
    return sum(1 for r in rows if r[key] >= cut) / len(rows) if rows else 0.0


def write_report(rows, dropped) -> None:
    by_year = defaultdict(list)
    for r in rows:
        by_year[r["year"]].append(r)
    n = len(rows)

    L = [
        "# Shipped models vs 2024–2025 phishing",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `python -m ml.evaluate_modern`.",
        "",
        "Models trained on 2004–2007 phishing and 2002 benign mail, tested unchanged on phishing written "
        "about 20 years later. Test only: none of this data was used for training. Recall only: with no "
        "modern legitimate mail, false positives cannot be measured.",
        "",
        f"**{n} modern phishing emails** after removing {dropped.get('duplicate_of_training', 0)} duplicates of "
        f"training mail, {dropped.get('duplicate_within_modern', 0)} duplicates within the set, and "
        f"{dropped.get('unparseable', 0)} unparseable messages. By year: "
        + ", ".join(f"{y}: {len(v)}" for y, v in sorted(by_year.items())) + ".",
        "",
        "## Recall: did it hold up?",
        "",
        "| Configuration | 2007 phishing, unseen (reference) | 2024–2025 phishing | Change |",
        "| :--- | ---: | ---: | ---: |",
    ]
    for label, key in (("Rules + LR", "rules_lr"), ("Rules + LR + text", "rules_lr_text")):
        for i, (cut, name) in enumerate(((MALICIOUS_THRESHOLD, "MALICIOUS ≥61"), (SUSPICIOUS_THRESHOLD, "SUSPICIOUS+ ≥21"))):
            ref, now = IN_ERA[label][i], recall(rows, key, cut)
            L.append(f"| {label} @ {name} | {ref:.1%} | {now:.1%} | {now - ref:+.1%} |")
    L += [
        f"| Rules only @ MALICIOUS ≥61 | — | {recall(rows, 'rules', MALICIOUS_THRESHOLD):.1%} | |",
        f"| Rules only @ SUSPICIOUS+ ≥21 | — | {recall(rows, 'rules', SUSPICIOUS_THRESHOLD):.1%} | |",
        "",
        "## Modern-lure rules: before and after",
        "",
        f"The modern-lure rules were designed by reading {DESIGN_YEAR} phishing only. {HELD_OUT_YEAR} was "
        "not looked at while designing them, so the held-out row is the honest measure.",
        "",
        "| Year | Role | Emails | Rules + LR + text @ SUSPICIOUS+ (before → after) | @ MALICIOUS (before → after) | Rules only @ SUSPICIOUS+ |",
        "| :--- | :--- | ---: | ---: | ---: | ---: |",
    ]
    for year, rs in sorted(by_year.items()):
        role = "design" if year == DESIGN_YEAR else "**held out**" if year == HELD_OUT_YEAR else ""
        mal_b, sus_b = BEFORE_MODERN_RULES.get(year, (float("nan"), float("nan")))
        mal_a, sus_a = recall(rs, "rules_lr_text", MALICIOUS_THRESHOLD), recall(rs, "rules_lr_text", SUSPICIOUS_THRESHOLD)
        L.append(f"| {year} | {role} | {len(rs)} | {sus_b:.1%} → **{sus_a:.1%}** | {mal_b:.1%} → {mal_a:.1%} | "
                 f"{recall(rs, 'rules', SUSPICIOUS_THRESHOLD):.1%} |")
    L += ["", "Modern-lure rule fire rates per year:", "",
          "| Rule | " + " | ".join(str(y) for y in sorted(by_year)) + " |",
          "| :--- | " + " | ".join("---:" for _ in by_year) + " |"]
    for rule in sorted(MODERN_RULES):
        cells = [f"{sum(1 for r in rs if rule in r['fired']) / len(rs):.1%}" for _, rs in sorted(by_year.items())]
        L.append(f"| `{rule}` | " + " | ".join(cells) + " |")

    lr_rate = sum(r["lr_flag"] for r in rows) / n
    text_rate = sum(r["text_flag"] for r in rows) / n
    text_neg = sum(1 for r in rows if r["text_points"] < 0) / n
    oov = sum(r["oov"] for r in rows) / n
    empty = sum(r["empty_text"] for r in rows)
    L += [
        "",
        "## The two learned models on their own",
        "",
        "| Model | 2007 unseen (reference) | 2024–2025 |",
        "| :--- | ---: | ---: |",
        f"| Structured LR, flags as phishing | 71.9% | {lr_rate:.1%} |",
        f"| Text model, flags as phishing | 89.0% | {text_rate:.1%} |",
        "",
        f"- The text model **pushed the score down** (negative points) on {text_neg:.1%} of modern phishing.",
        f"- **Vocabulary drift:** on average {oov:.1%} of a modern email's tokens are unknown to the text model "
        f"(it ignores them). {empty} emails had no readable text at all (image-only or empty bodies).",
        "",
        "## What fired",
        "",
        "Share of modern phishing on which each rule fired:",
        "",
        "| Rule | Fired on |",
        "| :--- | ---: |",
    ]
    fired = Counter(rule for r in rows for rule in set(r["fired"]))
    for rule, count in fired.most_common():
        L.append(f"| `{rule}` | {count / n:.1%} |")
    none_fired = sum(1 for r in rows if not r["fired"])
    L.append(f"| *(no rule at all)* | {none_fired / n:.1%} |")

    terms = Counter()
    for r in rows:
        for term, _ in r["top_terms"]:
            terms[term] += 1
    authres = sum(r["authres"] for r in rows)
    spf = Counter(r["spf"] for r in rows)
    L += [
        "",
        "Words the text model most often cited as evidence on modern phishing: "
        + ", ".join(f"`{t}` ({c})" for t, c in terms.most_common(15)) + ".",
        "",
        "## Authentication headers",
        "",
        f"{authres} of {n} modern emails ({authres / n:.1%}) carry an `Authentication-Results` header, versus "
        "none in the training corpus. SPF verdicts: " + ", ".join(f"{k} {v}" for k, v in spf.most_common()) + ".",
        "These headers are why the header rules can fire here when they could not in training.",
        "",
        "## Limits",
        "",
        "- **Recall only.** No modern legitimate mail, so no false-positive rate.",
        "- **One collector.** Every email reached one person's inbox; other organisations see different phishing.",
        "- **Link shorteners were not resolved** (offline run); in production they would be.",
        "",
        "## Attribution",
        "",
        "Test data: Jose Nazario, *phishing corpus* (phishing-2024, phishing-2025), "
        "https://monkey.org/~jose/phishing/, licensed CC-BY-4.0. Used unmodified except for "
        "deduplication; only aggregate results are reported.",
        "",
    ]
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        handle.write("\n".join(L))
    print("\n".join(L))


if __name__ == "__main__":
    raise SystemExit(main())
