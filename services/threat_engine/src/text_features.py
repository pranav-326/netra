"""Text cleaning and tokenisation for the learned text channel (Layer 4).

The single implementation used by both the offline trainer (ml/train_text_model.py)
and the online scorer (text_scorer.py). Any change here changes both sides at once,
which is the point: training and serving can never tokenise differently.

Cleaning removes what identifies a *dataset* or an *era* rather than phishing
language. Our corpora pair 2002 mailing-list ham with 2004–2007 phishing, so dates,
quoted replies, signatures and list footers would otherwise let a model tell the
two apart without learning anything about phishing. URLs and addresses are replaced
by placeholders because the URL engine already analyses them properly.
"""

import html
import re
from typing import List, Optional

# Bounds inference cost per email; applied identically in training.
MAX_WORDS = 2000
CHAR_NGRAM_SIZES = (3, 4, 5)

# Tokens that identify where our training data came from rather than whether an
# email is phishing, found in the first model's top terms (see
# ml/reports/text_model_evaluation.md). Dropped before any n-gram is built.
DATASET_ARTIFACTS: frozenset = frozenset({
    # Mailing-list reply structure and the "URL: ... Date: Not supplied" feed layout.
    "re", "wrote", "url", "date", "supplied",
    # SpamAssassin's address anonymisation, list names, and the phishing corpus's inbox.
    "zzzz", "zzz", "zzzzteana", "zzzzcc", "zzzlist", "spamassassin", "taint",
    "sourceforge", "exmh", "razor", "ilug", "jmason", "freshrpms", "lockergnome",
    "jose", "monkey", "nazario",
    # Dates and times survive digit stripping as words. "may" stays: it is a real word
    # in phishing ("your account may be suspended").
    "pm",
    "jan", "feb", "mar", "apr", "jun", "jul", "aug", "sep", "sept", "oct", "nov", "dec",
    "january", "february", "march", "april", "june", "july", "august", "september",
    "october", "november", "december",
    "mon", "tue", "tues", "wed", "thu", "thur", "thurs", "fri", "sat", "sun",
    "monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday",
})

_URL = re.compile(r"(?:https?://|hxxps?://|www\.)\S+", re.IGNORECASE)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_DIGITS = re.compile(r"\d+")
_TAG = re.compile(r"<[^>]+>")
_STYLE_SCRIPT = re.compile(r"<(style|script)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
_WORD = re.compile(r"[a-z]{2,}")
_FOOTER_MARKERS = (
    "unsubscribe",
    "mailing list",
    "listinfo",
    "list-id",
    "yahoo! groups",
    "sponsored by",
)


def html_to_text(markup: str) -> str:
    return html.unescape(_TAG.sub(" ", _STYLE_SCRIPT.sub(" ", markup)))


def clean_text(subject: Optional[str], body_plain: Optional[str], body_html: Optional[str]) -> str:
    """The text the model sees: subject plus body, minus dataset and era artifacts."""
    body = body_plain if (body_plain or "").strip() else html_to_text(body_html or "")

    kept: List[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped in ("--", "-- "):
            break  # RFC 3676 signature delimiter
        if len(stripped) >= 15 and set(stripped) <= set("_-="):
            break  # mailing-list footer or reply separator
        if stripped.startswith(">"):
            continue  # quoted reply
        lowered = stripped.lower()
        if any(marker in lowered for marker in _FOOTER_MARKERS):
            continue
        kept.append(line)

    text = f"{subject or ''}\n" + "\n".join(kept)
    text = _URL.sub(" urltoken ", text)
    text = _EMAIL.sub(" emailtoken ", text)
    text = _DIGITS.sub(" ", text)
    return text.lower()


def tokenize(text: str) -> List[str]:
    """Word unigrams (w:), word bigrams (w2:) and in-word character n-grams (c:)."""
    words = [w for w in _WORD.findall(text) if w not in DATASET_ARTIFACTS][:MAX_WORDS]

    tokens = [f"w:{w}" for w in words]
    tokens.extend(f"w2:{a} {b}" for a, b in zip(words, words[1:]))
    for w in words:
        padded = f" {w} "
        for n in CHAR_NGRAM_SIZES:
            tokens.extend(f"c:{padded[i:i + n]}" for i in range(len(padded) - n + 1))
    return tokens
