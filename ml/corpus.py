"""Turn labelled .eml corpora into the model's feature matrix.

Crucially, this runs the **production** parser and analyzer over every corpus message
rather than reimplementing extraction for training. A second implementation would
drift from the first, and the resulting train/serve skew is invisible: the model
would look excellent offline and behave differently in the pipeline.

Usage:
    python -m ml.corpus --phishing data/phishing --benign data/benign --out data/features.jsonl
"""

import argparse
import json
import logging
import os
import sys
import uuid
from typing import Dict, Iterator, List, Optional, Tuple

# Make the service packages importable when running from the repo root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "services", "parser"))

from services.analyzer.src.engines import (  # noqa: E402
    analyze_attachments,
    analyze_content,
    analyze_headers,
    analyze_urls,
)
from services.threat_engine.src.features import extract_features  # noqa: E402
from netra_common.models.email import AnalysisResults, AnalyzedEmail  # noqa: E402

logging.basicConfig(level=logging.WARNING, format="%(levelname)s: %(message)s")
logger = logging.getLogger("netra.ml.corpus")

EML_SUFFIXES = (".eml", ".txt", ".msg", "")


def _build_parser():
    """Construct the real parser worker with no Redis or MinIO attached."""
    from src.worker import EmailParserWorker  # noqa: E402  (resolved via sys.path)

    return EmailParserWorker(connect=False)


def analyze_raw_email(parser, raw_bytes: bytes, email_id: str, resolver=None) -> AnalyzedEmail:
    """Run the production Layer 2 and Layer 3 path over one raw message.

    Link shorteners are not resolved by default: corpus work is offline, and years-old
    short links are dead anyway. Pass a ShortenerResolver to opt in.
    """
    parsed = parser.parse_rfc5322(
        raw_bytes=raw_bytes,
        email_id=email_id,
        bucket="corpus",
        object_key=f"{email_id}.eml",
    )

    analysis = AnalysisResults(
        header_analysis=analyze_headers(parsed.headers),
        url_analysis=analyze_urls(parsed.extracted_urls, resolver=resolver),
        content_analysis=analyze_content(parsed.body_plain, parsed.body_html, parsed.headers.subject),
        attachment_analysis=analyze_attachments(parsed.attachments),
    )
    return AnalyzedEmail(email_id=email_id, parsed_email=parsed, analysis=analysis)


def iter_corpus_files(root: str) -> Iterator[str]:
    """Yield candidate email files under `root`, recursively."""
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            if name.startswith("."):
                continue
            if name.lower().endswith((".json", ".csv", ".md", ".gz", ".zip", ".tar")):
                continue
            yield os.path.join(dirpath, name)


def build_split(
    parser, root: str, label: int, source: str, limit: Optional[int] = None
) -> Tuple[List[Dict], int]:
    """Featurise every message under `root`, returning rows and a failure count."""
    rows: List[Dict] = []
    failures = 0

    for count, path in enumerate(iter_corpus_files(root)):
        if limit is not None and len(rows) >= limit:
            break
        try:
            with open(path, "rb") as handle:
                raw = handle.read()
            if not raw.strip():
                continue

            analyzed = analyze_raw_email(parser, raw, str(uuid.uuid4()))
            features = extract_features(analyzed)

            rows.append({
                "label": label,
                "source": source,
                "path": os.path.relpath(path, root),
                "features": features,
            })
        except Exception as exc:
            failures += 1
            logger.debug(f"Skipped {path}: {exc}")

        if count and count % 500 == 0:
            print(f"  ...{len(rows)} parsed from {source}", flush=True)

    return rows, failures


def main() -> int:
    ap = argparse.ArgumentParser(description="Featurise labelled email corpora.")
    ap.add_argument("--phishing", action="append", default=[], help="Directory of phishing .eml (repeatable)")
    ap.add_argument("--benign", action="append", default=[], help="Directory of benign .eml (repeatable)")
    ap.add_argument("--out", required=True, help="Output JSONL path")
    ap.add_argument("--limit-per-dir", type=int, default=None, help="Cap messages read per directory")
    args = ap.parse_args()

    if not args.phishing or not args.benign:
        ap.error("at least one --phishing and one --benign directory are required")

    parser = _build_parser()
    all_rows: List[Dict] = []
    total_failures = 0

    for directory in args.phishing:
        print(f"Featurising phishing corpus: {directory}")
        rows, failures = build_split(parser, directory, 1, os.path.basename(directory.rstrip("/")), args.limit_per_dir)
        all_rows.extend(rows)
        total_failures += failures
        print(f"  {len(rows)} messages, {failures} unreadable")

    for directory in args.benign:
        print(f"Featurising benign corpus: {directory}")
        rows, failures = build_split(parser, directory, 0, os.path.basename(directory.rstrip("/")), args.limit_per_dir)
        all_rows.extend(rows)
        total_failures += failures
        print(f"  {len(rows)} messages, {failures} unreadable")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        for row in all_rows:
            handle.write(json.dumps(row) + "\n")

    positives = sum(r["label"] for r in all_rows)
    print(
        f"\nWrote {len(all_rows)} rows to {args.out} "
        f"({positives} phishing / {len(all_rows) - positives} benign, {total_failures} unreadable)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
