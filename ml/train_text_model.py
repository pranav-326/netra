"""Evaluate, and optionally train, the learned text channel (ML-TEXT) for Layer 4.

Answers one question honestly: does a linear model over the email's words beat the
current structured-feature model, once the corpus's era and dataset artifacts are
controlled for?

Our phishing corpus is 2004–2007 and our benign corpus is 2002 mailing-list mail, so
a text model can win by recognising the era or the source instead of phishing. The
evaluation therefore deduplicates, cleans the text (text_features.clean_text), tests
on a split grouped by source mbox, measures how well era tokens alone predict the
label, and reports results before and after a dataset-artifact stoplist.

Ship rule, fixed before any result was seen: rules + LR + text must beat rules + LR on
the grouped split in PR AUC AND in recall at the MALICIOUS threshold, with precision
there dropping by no more than one point.

Usage:
    python -m ml.train_text_model                 # evaluate, write the report
    python -m ml.train_text_model --ship          # also train and write the artifact
    python -m ml.train_text_model --rebuild-cache # re-parse the corpus first
"""

import argparse
import hashlib
import json
import mailbox
import os
import re
import sys
import time
import uuid
from collections import Counter
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Dict, List, Tuple

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import numpy as np  # noqa: E402
from sklearn.base import BaseEstimator, ClassifierMixin  # noqa: E402

from ml.corpus import _build_parser, analyze_raw_email  # noqa: E402
from netra_common.models.email import AnalysisResults  # noqa: E402
from services.threat_engine.src import text_features  # noqa: E402
from services.threat_engine.src.features import extract_features  # noqa: E402
from services.threat_engine.src.ml_scorer import MLPrediction, MLScorer  # noqa: E402
from services.threat_engine.src.scorer import (  # noqa: E402
    MALICIOUS_THRESHOLD,
    SUSPICIOUS_THRESHOLD,
    apply_ml_contribution,
    apply_text_contribution,
    evaluate_threat_score,
    finalize_score,
)
from services.threat_engine.src.text_scorer import TextPrediction  # noqa: E402

DATA = os.path.join(REPO_ROOT, "data")
CACHE_PATH = os.path.join(DATA, "text_corpus.jsonl")
LR_ARTIFACT = os.path.join(REPO_ROOT, "services", "threat_engine", "src", "models", "phish_lr.json")
TEXT_ARTIFACT = os.path.join(REPO_ROOT, "services", "threat_engine", "src", "models", "text_lr.json")
REPORT_PATH = os.path.join(REPO_ROOT, "ml", "reports", "text_model_evaluation.md")

SEED = 42
TARGET_PRECISION = 0.95
LR_MAX_POINTS = 25
TEXT_MAX_POINTS = 15
MIN_WORDS_FOR_DEDUP = 20
VOCAB_SIZE = 20000
MIN_DF = 3

GROUPED_TRAIN = {"phishing0", "phishing1", "phishing2", "easy_ham"}
GROUPED_TEST = {"phishing3", "hard_ham"}

# Tokens that date or source a message rather than describe it, for the era detector.
ERA_KEYWORDS = (
    "spamassassin", "sourceforge", "exmh", "razor", "zzzz", "jmason", "yahoogroups",
    "egroups", "lockergnome", "xent", "fork", "ilug", "linux.ie", "monkey.org", "jose",
    "freshrpms", "rpm-list", "listman", "mailman", "majordomo",
)
_YEAR = re.compile(r"\b(19[89]\d|20[0-3]\d)\b")
_MAILER = re.compile(r"^(x-mailer|user-agent):\s*([A-Za-z]+)", re.IGNORECASE | re.MULTILINE)
_LIST_HEADER = re.compile(r"^(list-id|list-unsubscribe|mailing-list|x-mailing-list):", re.IGNORECASE | re.MULTILINE)


# ---------------------------------------------------------------------------
# Corpus
# ---------------------------------------------------------------------------

def _phishing_group_bounds() -> List[Tuple[int, str]]:
    """File index at which each phishing mbox ends; files were split from them in order."""
    bounds, offset = [], 0
    for i in range(3):
        offset += len(mailbox.mbox(os.path.join(DATA, f"phishing{i}.mbox")))
        bounds.append((offset, f"phishing{i}"))
    return bounds


def _iter_sources():
    bounds = _phishing_group_bounds()
    phish_dir = os.path.join(DATA, "phishing")
    for name in sorted(os.listdir(phish_dir)):
        if not name.endswith(".eml"):
            continue
        index = int(re.search(r"(\d+)", name).group(1))
        group = next((g for end, g in bounds if index < end), "phishing3")
        yield os.path.join(phish_dir, name), group, 1
    for group in ("easy_ham", "hard_ham"):
        folder = os.path.join(DATA, "benign", group)
        for name in sorted(os.listdir(folder)):
            if not name.startswith("."):
                yield os.path.join(folder, name), group, 0


def build_cache() -> None:
    parser = _build_parser()
    written = failed = 0
    started = time.time()
    with open(CACHE_PATH, "w", encoding="utf-8") as out:
        for path, group, label in _iter_sources():
            try:
                raw = open(path, "rb").read()
                analyzed = analyze_raw_email(parser, raw, str(uuid.uuid4()), resolver=None)
                parsed = analyzed.parsed_email
                head = re.split(rb"\r?\n\r?\n", raw, maxsplit=1)[0].decode("latin-1")[:20000]
                out.write(json.dumps({
                    "path": os.path.relpath(path, DATA),
                    "group": group,
                    "label": label,
                    "subject": parsed.headers.subject,
                    "body_plain": parsed.body_plain,
                    "body_html": parsed.body_html,
                    "raw_head": head,
                    "features": extract_features(analyzed),
                    "analysis": analyzed.analysis.model_dump(mode="json"),
                }) + "\n")
                written += 1
            except Exception:
                failed += 1
            if (written + failed) % 1000 == 0:
                print(f"  parsed {written + failed} ({time.time() - started:.0f}s)", flush=True)
    print(f"Cache: {written} emails parsed, {failed} unparseable -> {CACHE_PATH}")


def load_cache() -> List[dict]:
    with open(CACHE_PATH, "r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle]


def deduplicate(records: List[dict]) -> Tuple[List[dict], Dict[str, int]]:
    """Drop exact copies (identical body) and near copies (identical cleaned words).

    Very short texts are exempt from near-duplicate collapsing: an empty body is not
    a copy of every other empty body.
    """
    seen_exact, seen_near = {}, {}
    kept, stats = [], Counter()
    for rec in records:
        body = " ".join(((rec["subject"] or "") + " " + (rec["body_plain"] or rec["body_html"] or "")).split())
        exact = hashlib.sha1(body.encode("utf-8", "ignore")).hexdigest()
        words = re.findall(r"[a-z]{2,}", text_features.clean_text(rec["subject"], rec["body_plain"], rec["body_html"]))
        near = hashlib.sha1(" ".join(words).encode()).hexdigest() if len(words) >= MIN_WORDS_FOR_DEDUP else None

        if exact in seen_exact:
            stats["exact"] += 1
            stats["cross_label"] += seen_exact[exact] != rec["label"]
            continue
        if near and near in seen_near:
            stats["near"] += 1
            stats["cross_label"] += seen_near[near] != rec["label"]
            continue
        seen_exact[exact] = rec["label"]
        if near:
            seen_near[near] = rec["label"]
        kept.append(rec)
    return kept, dict(stats)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

def choose_threshold(y, proba) -> float:
    """Highest-recall threshold meeting TARGET_PRECISION, else best F1 (as train_scorer)."""
    import numpy as np
    from sklearn.metrics import precision_recall_curve

    precision, recall, thresholds = precision_recall_curve(y, proba)
    best_t, best_r = None, -1.0
    for p, r, t in zip(precision[:-1], recall[:-1], thresholds):
        if p >= TARGET_PRECISION and r > best_r:
            best_t, best_r = float(t), float(r)
    if best_t is None:
        f1 = 2 * precision[:-1] * recall[:-1] / np.clip(precision[:-1] + recall[:-1], 1e-9, None)
        best_t = float(thresholds[int(np.argmax(f1))])
    return best_t


def struct_pipeline():
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    return Pipeline([
        ("scale", StandardScaler()),
        ("lr", LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000, random_state=SEED)),
    ])


def text_pipeline():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline

    return Pipeline([
        # Documents arrive pre-tokenised by text_features.tokenize: sklearn only counts.
        ("tfidf", TfidfVectorizer(analyzer=_identity, sublinear_tf=True, min_df=MIN_DF,
                                  max_features=VOCAB_SIZE, dtype=np.float64)),
        ("lr", LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000,
                                  solver="liblinear", random_state=SEED)),
    ])


def _identity(tokens):
    return tokens


def count_matrix(tokens):
    """Raw token counts for every email, over every token seen. Label-free."""
    from sklearn.feature_extraction.text import CountVectorizer

    vectorizer = CountVectorizer(analyzer=_identity, dtype=np.float64)
    return vectorizer.fit_transform(tokens).tocsr(), vectorizer.get_feature_names_out()


class CountsTextModel(ClassifierMixin, BaseEstimator):
    """text_pipeline() over a precomputed count matrix, for fast cross-validation.

    Chooses the vocabulary from the TRAINING rows only, by the same rule as
    TfidfVectorizer(min_df=MIN_DF, max_features=VOCAB_SIZE): tokens in at least MIN_DF
    documents, top VOCAB_SIZE by total count. Idf, sublinear tf and the l2 norm then
    match TfidfVectorizer on that vocabulary, so this reproduces the shipped model
    without re-tokenising the corpus in every fold.
    """

    def fit(self, X, y):
        import numpy as np
        from sklearn.feature_extraction.text import TfidfTransformer
        from sklearn.linear_model import LogisticRegression

        df = np.asarray((X > 0).sum(axis=0)).ravel()
        tf = np.asarray(X.sum(axis=0)).ravel()
        eligible = np.where(df >= MIN_DF)[0]
        self.cols_ = np.sort(eligible[np.argsort(-tf[eligible], kind="stable")][:VOCAB_SIZE])
        self.tfidf_ = TfidfTransformer(sublinear_tf=True).fit(X[:, self.cols_])
        self.lr_ = LogisticRegression(C=1.0, class_weight="balanced", max_iter=2000,
                                      solver="liblinear", random_state=SEED)
        self.lr_.fit(self.tfidf_.transform(X[:, self.cols_]), y)
        self.classes_ = self.lr_.classes_
        return self

    def predict_proba(self, X):
        return self.lr_.predict_proba(self.tfidf_.transform(X[:, self.cols_]))

    def predict(self, X):
        return self.lr_.predict(self.tfidf_.transform(X[:, self.cols_]))


def fit_predict(make_model, X, y, train_idx, test_idx):
    """Fit on train, predict test; threshold chosen from out-of-fold train predictions."""
    import numpy as np
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    X_train, X_test = X[train_idx], X[test_idx]
    y_train = y[train_idx]

    inner = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    oof = cross_val_predict(make_model(), X_train, y_train, cv=inner, method="predict_proba")[:, 1]
    threshold = choose_threshold(y_train, oof)

    model = make_model().fit(X_train, y_train)
    return np.asarray(model.predict_proba(X_test)[:, 1]), threshold


def to_points(probability: float, threshold: float, max_points: int) -> int:
    # Reuse the production mapping exactly; it only reads these two attributes.
    return MLScorer._to_points(SimpleNamespace(threshold=threshold, max_points=max_points), probability)


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------

def score_email(analysis: AnalysisResults, lr_points: int, text_points=None) -> Tuple[int, int]:
    """Return (rules-only raw score, full raw score) through the production scorer."""
    _, _, _, rules, _ = evaluate_threat_score(analysis)
    rules_raw = finalize_score(rules)[3]
    prediction = MLPrediction(probability=0.0, logit=0.0, points=lr_points)
    contributions = apply_ml_contribution(list(rules), prediction)
    if text_points is not None:
        # The production function, so the evaluation scores exactly as serving will.
        text_prediction = TextPrediction(probability=0.0, logit=0.0, points=text_points,
                                         threshold=0.0, model_version="cv")
        contributions = apply_text_contribution(contributions, text_prediction)
    return rules_raw, finalize_score(contributions)[3]


def at_threshold(y, scores, threshold) -> Dict[str, float]:
    tp = sum(1 for t, s in zip(y, scores) if t == 1 and s >= threshold)
    fp = sum(1 for t, s in zip(y, scores) if t == 0 and s >= threshold)
    fn = sum(1 for t, s in zip(y, scores) if t == 1 and s < threshold)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": precision, "recall": recall, "tp": tp, "fp": fp, "fn": fn}


def run_split(name, records, X_text, X_struct, y, folds) -> dict:
    """Collect out-of-sample predictions and scores over the given (train, test) folds."""
    import numpy as np
    from sklearn.metrics import average_precision_score

    n = len(records)
    p_lr, p_tx = np.zeros(n), np.zeros(n)
    t_lr, t_tx = np.zeros(n), np.zeros(n)
    tested = np.zeros(n, dtype=bool)

    for train_idx, test_idx in folds:
        p, t = fit_predict(struct_pipeline, X_struct, y, train_idx, test_idx)
        p_lr[test_idx], t_lr[test_idx] = p, t
        p, t = fit_predict(CountsTextModel, X_text, y, train_idx, test_idx)
        p_tx[test_idx], t_tx[test_idx] = p, t
        tested[test_idx] = True

    idx = np.where(tested)[0]
    y_t = y[idx]
    rules_raw, raw_a, raw_b = [], [], []
    for i in idx:
        analysis = AnalysisResults.model_validate(records[i]["analysis"])
        lr_pts = to_points(p_lr[i], t_lr[i], LR_MAX_POINTS)
        tx_pts = to_points(p_tx[i], t_tx[i], TEXT_MAX_POINTS)
        r, a = score_email(analysis, lr_pts)
        _, b = score_email(analysis, lr_pts, tx_pts)
        rules_raw.append(r)
        raw_a.append(a)
        raw_b.append(b)

    lr_flag = [int(p_lr[i] >= t_lr[i]) for i in idx]
    tx_flag = [int(p_tx[i] >= t_tx[i]) for i in idx]
    result = {
        "name": name,
        "n_test": int(len(idx)),
        "n_phish": int(y_t.sum()),
        "rows": {
            "Current LR (model only)": {
                "pr_auc": average_precision_score(y_t, p_lr[idx]), **at_threshold(y_t, lr_flag, 1)},
            "Text model only": {
                "pr_auc": average_precision_score(y_t, p_tx[idx]), **at_threshold(y_t, tx_flag, 1)},
        },
    }
    for label, raw in (("Rules only", rules_raw), ("Rules + LR (current)", raw_a), ("Rules + LR + text", raw_b)):
        result["rows"][label] = {
            "pr_auc": average_precision_score(y_t, raw),
            "malicious": at_threshold(y_t, raw, MALICIOUS_THRESHOLD),
            "suspicious": at_threshold(y_t, raw, SUSPICIOUS_THRESHOLD),
        }

    for key, cut in (("malicious", MALICIOUS_THRESHOLD), ("suspicious", SUSPICIOUS_THRESHOLD)):
        missed = [k for k, t in enumerate(y_t) if t == 1 and raw_a[k] < cut]
        caught = sum(1 for k in missed if raw_b[k] >= cut)
        new_fp = sum(1 for k, t in enumerate(y_t) if t == 0 and raw_a[k] < cut <= raw_b[k])
        result[f"rescue_{key}"] = {"missed_by_current": len(missed), "caught_by_text": caught, "new_false_positives": new_fp}
    lr_missed = [k for k, t in enumerate(y_t) if t == 1 and not lr_flag[k]]
    result["lr_misses_caught_by_text_model"] = (len(lr_missed), sum(tx_flag[k] for k in lr_missed))
    return result


def era_check(records, y) -> Dict[str, float]:
    """How well do era and source tokens ALONE predict the label?"""
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_val_predict
    from sklearn.metrics import roc_auc_score

    def raw_tokens(rec):
        blob = (rec["raw_head"] or "") + "\n" + (rec["body_plain"] or "")
        feats = {f"year:{m}": 1 for m in _YEAR.findall(blob)}
        feats.update({f"mailer:{m[1].lower()}": 1 for m in _MAILER.findall(rec["raw_head"] or "")})
        if _LIST_HEADER.search(rec["raw_head"] or ""):
            feats["list_header"] = 1
        lowered = blob.lower()
        feats.update({f"kw:{k}": 1 for k in ERA_KEYWORDS if k in lowered})
        return feats

    def cleaned_tokens(rec):
        words = set(re.findall(r"[a-z.]{2,}", text_features.clean_text(rec["subject"], rec["body_plain"], rec["body_html"])))
        return {f"kw:{k}": 1 for k in ERA_KEYWORDS if k in words}

    out = {}
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    for label, fn in (("raw_message", raw_tokens), ("cleaned_text", cleaned_tokens)):
        X = DictVectorizer().fit_transform([fn(r) for r in records])
        proba = cross_val_predict(LogisticRegression(max_iter=2000, class_weight="balanced"), X, y, cv=cv,
                                  method="predict_proba")[:, 1]
        out[label] = roc_auc_score(y, proba)
    return out


def top_terms(X_text, names, y, n=40) -> Tuple[List[Tuple[str, float]], List[Tuple[str, float]]]:
    model = CountsTextModel().fit(X_text, y)
    vocab = names[model.cols_]
    coef = model.lr_.coef_[0]
    order = sorted(range(len(coef)), key=lambda i: coef[i])
    return ([(vocab[i], float(coef[i])) for i in reversed(order[-n:])],
            [(vocab[i], float(coef[i])) for i in order[:n]])


def evaluate(records, stoplist) -> dict:
    import numpy as np
    from sklearn.model_selection import StratifiedKFold

    text_features.DATASET_ARTIFACTS = frozenset(stoplist)
    with open(LR_ARTIFACT, "r", encoding="utf-8") as handle:
        lr_order = json.load(handle)["feature_order"]

    y = np.array([r["label"] for r in records])
    X_struct = np.array([[float(r["features"].get(f, 0.0)) for f in lr_order] for r in records])
    tokens = [text_features.tokenize(text_features.clean_text(r["subject"], r["body_plain"], r["body_html"]))
              for r in records]
    X_text, names = count_matrix(tokens)

    shuffled = list(StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED).split(X_struct, y))
    train = np.array([i for i, r in enumerate(records) if r["group"] in GROUPED_TRAIN])
    test = np.array([i for i, r in enumerate(records) if r["group"] in GROUPED_TEST])

    return {
        "shuffled": run_split("Shuffled stratified 5-fold", records, X_text, X_struct, y, shuffled),
        "grouped": run_split("Grouped by source (train phishing0-2 + easy_ham; test phishing3 + hard_ham)",
                             records, X_text, X_struct, y, [(train, test)]),
        "top_terms": top_terms(X_text, names, y),
    }


def passes_ship_rule(grouped: dict) -> Tuple[bool, str]:
    a, b = grouped["rows"]["Rules + LR (current)"], grouped["rows"]["Rules + LR + text"]
    checks = [
        (b["pr_auc"] > a["pr_auc"], f"PR AUC {a['pr_auc']:.4f} -> {b['pr_auc']:.4f}"),
        (b["malicious"]["recall"] > a["malicious"]["recall"],
         f"recall@MALICIOUS {a['malicious']['recall']:.4f} -> {b['malicious']['recall']:.4f}"),
        (b["malicious"]["precision"] >= a["malicious"]["precision"] - 0.01,
         f"precision@MALICIOUS {a['malicious']['precision']:.4f} -> {b['malicious']['precision']:.4f}"),
    ]
    return all(ok for ok, _ in checks), "; ".join(("PASS " if ok else "FAIL ") + msg for ok, msg in checks)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def _split_tables(res: dict) -> List[str]:
    lines = [f"**{res['name']}** — {res['n_test']} test emails ({res['n_phish']} phishing)", "",
             "| Configuration | PR AUC | Precision | Recall | FN |", "| :--- | ---: | ---: | ---: | ---: |"]
    for label in ("Current LR (model only)", "Text model only"):
        r = res["rows"][label]
        lines.append(f"| {label} (at its threshold) | {r['pr_auc']:.4f} | {r['precision']:.4f} | {r['recall']:.4f} | {r['fn']} |")
    for label in ("Rules only", "Rules + LR (current)", "Rules + LR + text"):
        r = res["rows"][label]
        for key, name in (("malicious", "MALICIOUS ≥61"), ("suspicious", "SUSPICIOUS+ ≥21")):
            m = r[key]
            lines.append(f"| {label} @ {name} | {r['pr_auc']:.4f} | {m['precision']:.4f} | {m['recall']:.4f} | {m['fn']} |")
    lines.append("")
    for key, name in (("malicious", "MALICIOUS"), ("suspicious", "SUSPICIOUS-or-above")):
        r = res[f"rescue_{key}"]
        lines.append(f"- At {name}: the current pipeline misses {r['missed_by_current']} phishing emails; "
                     f"adding text catches **{r['caught_by_text']}** of them and adds "
                     f"{r['new_false_positives']} new false positives.")
    total, caught = res["lr_misses_caught_by_text_model"]
    lines.append(f"- Model level: of {total} phishing emails the current LR misses, the text model catches {caught}.")
    return lines + [""]


def _terms_table(pos, neg, stoplist) -> List[str]:
    flag = lambda term: " ⚑" if any(s in term for s in stoplist | set(ERA_KEYWORDS)) else ""
    lines = ["| # | Toward phishing | coef | Toward benign | coef |", "| ---: | :--- | ---: | :--- | ---: |"]
    for i, ((pt, pc), (nt, nc)) in enumerate(zip(pos, neg), 1):
        lines.append(f"| {i} | `{pt}`{flag(pt)} | {pc:+.2f} | `{nt}`{flag(nt)} | {nc:+.2f} |")
    return lines


def write_report(meta, era, before, after, stoplist, verdict) -> None:
    ok, detail = verdict
    L = [
        "# Text channel (ML-TEXT) — evaluation",
        "",
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} by `python -m ml.train_text_model`.",
        "",
        "## Verdict",
        "",
        f"**{'SHIP' if ok else 'DO NOT SHIP'}.** Ship rule (fixed before evaluation): rules + LR + text must beat "
        "rules + LR on the grouped split in PR AUC and in recall at MALICIOUS, with precision dropping by at most "
        "one point.",
        "",
        f"Grouped split, after the stoplist: {detail}",
        "",
        "## Corpus",
        "",
        f"- {meta['parsed']} emails parsed; {meta['exact']} exact and {meta['near']} near duplicates removed "
        f"({meta['cross_label']} of them carried the opposite label to their twin); **{meta['kept']} kept**.",
        f"- By source after deduplication: {meta['by_group']}.",
        "- Phishing is 2004–2007 (Nazario corpus mboxes); benign is 2002 SpamAssassin ham. Every benign email "
        "predates every typical phishing email.",
        "",
        "## Era leakage check",
        "",
        "A classifier trained on era and source tokens alone (years, mailer names, mailing-list headers, "
        "list and dataset keywords):",
        "",
        "| What it sees | ROC AUC |",
        "| :--- | ---: |",
        f"| The raw message (headers + body) | {era['raw_message']:.4f} |",
        f"| The cleaned text the model actually reads | {era['cleaned_text']:.4f} |",
        "",
    ]
    if era["raw_message"] >= 0.9:
        L += ["> **The corpus is confounded.** Era and source tokens alone separate the classes almost "
              "perfectly in the raw messages. Any model given headers or dates would learn the era. "
              "The text channel reads cleaned text only; the second row shows how much of that "
              "signal survives cleaning.", ""]
    L += ["## Results before the stoplist", ""] + _split_tables(before["grouped"]) + _split_tables(before["shuffled"])
    L += ["### Top terms before the stoplist (⚑ = matches a dataset/era marker)", ""]
    L += _terms_table(*before["top_terms"], set(stoplist)) + [""]
    L += ["## Stoplist", "", "Tokens removed as dataset or era artifacts after inspecting the terms above:", "",
          ", ".join(f"`{s}`" for s in sorted(stoplist)) or "(none)", ""]
    L += ["## Results after the stoplist (these decide the verdict)", ""]
    L += _split_tables(after["grouped"]) + _split_tables(after["shuffled"])
    L += ["### Top terms after the stoplist", ""] + _terms_table(*after["top_terms"], set(stoplist)) + [""]
    L += [
        "## Limits that no split here can fix",
        "",
        "- **Topic confound.** Benign mail is technical mailing-list discussion; phishing is banking and account "
        "language. A text model can learn 'finance talk = phishing', which would flag legitimate invoices and "
        "bank notices. No split within this corpus can detect that; only recent, in-domain benign mail can.",
        "- **Grouped test prevalence.** The grouped test set is mostly phishing (hard_ham has 250 emails), so "
        "absolute precision there is flattering. Compare configurations against each other, not to other reports.",
        "- **No authentication signal.** The corpora lack Authentication-Results headers, so header rules fire "
        "the same way on both classes.",
        "",
    ]
    os.makedirs(os.path.dirname(REPORT_PATH), exist_ok=True)
    with open(REPORT_PATH, "w", encoding="utf-8") as handle:
        handle.write("\n".join(L))


# ---------------------------------------------------------------------------
# Shipping
# ---------------------------------------------------------------------------

def train_and_write_artifact(records, detail: str) -> None:
    import numpy as np
    from sklearn.model_selection import StratifiedKFold, cross_val_predict

    from services.threat_engine.src.text_scorer import TextScorer

    y = np.array([r["label"] for r in records])
    tokens = [text_features.tokenize(text_features.clean_text(r["subject"], r["body_plain"], r["body_html"]))
              for r in records]

    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=SEED)
    oof = cross_val_predict(text_pipeline(), tokens, y, cv=cv, method="predict_proba")[:, 1]
    threshold = choose_threshold(y, oof)

    model = text_pipeline().fit(tokens, y)
    tfidf, lr = model.named_steps["tfidf"], model.named_steps["lr"]
    vocab = tfidf.get_feature_names_out()
    artifact = {
        "version": datetime.now(timezone.utc).strftime("text-lr-%Y%m%d-%H%M"),
        "model_type": "logistic_regression_tfidf",
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "tokenizer": {
            "max_words": text_features.MAX_WORDS,
            "char_ngram_sizes": list(text_features.CHAR_NGRAM_SIZES),
            "dataset_artifacts": sorted(text_features.DATASET_ARTIFACTS),
            "sublinear_tf": True,
            "norm": "l2",
        },
        "intercept": float(lr.intercept_[0]),
        "threshold": threshold,
        "max_points": TEXT_MAX_POINTS,
        # term -> [idf, coefficient]; idf is needed for every term to reproduce the l2 norm.
        "terms": {t: [float(i), float(c)] for t, i, c in zip(vocab, tfidf.idf_, lr.coef_[0])},
        "evaluation": {"samples": int(len(y)), "phishing": int(y.sum()), "grouped_split": detail},
    }
    with open(TEXT_ARTIFACT, "w", encoding="utf-8") as handle:
        json.dump(artifact, handle, separators=(",", ":"))

    # Parity: the pure-Python serving path must reproduce sklearn exactly.
    scorer = TextScorer(TEXT_ARTIFACT)
    sample = list(range(0, len(records), max(1, len(records) // 300)))
    expected = model.predict_proba([tokens[i] for i in sample])[:, 1]
    got = [scorer.probability_from_tokens(tokens[i]) for i in sample]
    worst = max(abs(a - b) for a, b in zip(expected, got))
    if worst > 1e-9:
        os.remove(TEXT_ARTIFACT)
        raise SystemExit(f"Parity check FAILED (max |diff| = {worst:.2e}); artifact removed.")
    size = os.path.getsize(TEXT_ARTIFACT) / 1e6
    print(f"Wrote {TEXT_ARTIFACT} ({size:.1f} MB, {len(vocab)} terms, threshold {threshold:.4f}); "
          f"parity with sklearn on {len(sample)} emails: max |diff| {worst:.1e}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--rebuild-cache", action="store_true")
    ap.add_argument("--ship", action="store_true", help="Train and write the artifact if the ship rule passes")
    args = ap.parse_args()

    if args.rebuild_cache or not os.path.exists(CACHE_PATH):
        build_cache()

    records = load_cache()
    kept, dup = deduplicate(records)
    by_group = Counter(r["group"] for r in kept)
    meta = {"parsed": len(records), "kept": len(kept), "exact": dup.get("exact", 0), "near": dup.get("near", 0),
            "cross_label": dup.get("cross_label", 0), "by_group": dict(sorted(by_group.items()))}
    print(f"Corpus: {meta}")

    import numpy as np
    y = np.array([r["label"] for r in kept])
    era = era_check(kept, y)
    print(f"Era detector ROC AUC: raw {era['raw_message']:.4f}, cleaned {era['cleaned_text']:.4f}")

    stoplist = set(text_features.DATASET_ARTIFACTS)
    before = evaluate(kept, set())
    after = evaluate(kept, stoplist) if stoplist else before
    verdict = passes_ship_rule(after["grouped"])
    write_report(meta, era, before, after, stoplist, verdict)

    for label, res in (("BEFORE stoplist", before), ("AFTER stoplist", after)):
        print(f"\n=== {label} ===")
        for split in ("grouped", "shuffled"):
            print("\n".join(_split_tables(res[split])))
    print("\nTop terms (after):")
    print("\n".join(_terms_table(*after["top_terms"], stoplist)))
    print(f"\nVerdict: {'SHIP' if verdict[0] else 'DO NOT SHIP'} — {verdict[1]}")
    print(f"Report -> {REPORT_PATH}")

    if args.ship:
        if not verdict[0]:
            print("Not shipping: the ship rule failed.")
            return 0
        train_and_write_artifact(kept, verdict[1])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
