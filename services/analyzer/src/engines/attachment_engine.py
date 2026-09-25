"""Attachment Security Analysis Engine (Layer 3)
Evaluates email attachments for inherently dangerous file extensions,
double-extension evasion tactics, and MIME-type vs. file extension discrepancies.
"""

import os
import re
from typing import List
from netra_common.models.email import AttachmentMetadata, AttachmentAnalysisResult, FlaggedAttachment

# Inherently dangerous, executable, or macro-enabled extensions
DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".vbs", ".js", ".jse", ".bat", ".cmd", ".ps1",
    ".iso", ".img", ".hta", ".wsf", ".wsh", ".jar", ".msi", ".msp",
    ".cpl", ".reg", ".dll", ".com", ".docm", ".xlsm", ".pptm", ".dotm",
    ".xltm", ".chm", ".lnk", ".inf", ".pif", ".vb"
}

# Attached web pages: open locally in a browser, render a fake login form, and post
# credentials to the attacker, with no link for a URL filter to inspect.
HTML_EXTENSIONS = {".html", ".htm", ".shtml", ".xhtml", ".mht", ".mhtml", ".svg"}

# Regex pattern to catch double extensions commonly used to trick users (e.g. invoice.pdf.exe)
DOUBLE_EXTENSION_PATTERN = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|jpe?g|png|txt|zip|tar|gz)\.(?:exe|scr|vbs|js|bat|cmd|ps1|hta|iso|jar|msi|cpl)$",
    re.IGNORECASE
)

# Common benign MIME type to extension mappings for mismatch detection
DOCUMENT_MIMES = {
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "image/jpeg",
    "image/png",
    "image/gif",
    "text/plain",
}

EXECUTABLE_MIMES = {
    "application/x-msdownload",
    "application/x-dosexec",
    "application/x-executable",
    "application/x-bat",
    "application/x-sh",
    "application/x-msi",
}


def analyze_attachments(attachments: List[AttachmentMetadata]) -> AttachmentAnalysisResult:
    """Analyze attachments for malicious indicators and masking tactics."""
    if not attachments:
        return AttachmentAnalysisResult()

    has_executable = False
    has_double_ext = False
    has_mime_mismatch = False
    flagged: List[FlaggedAttachment] = []
    html_files: List[str] = []

    for att in attachments:
        filename = att.filename or "unnamed"
        claimed_mime = (att.content_type or "").lower().strip()

        # Extract extension
        _, ext = os.path.splitext(filename.lower())

        # Kept apart from flagged_attachments: an HTML file is a delivery vector for a fake
        # login page, not an executable, and the learned model's inputs stay unchanged.
        if ext in HTML_EXTENSIONS:
            html_files.append(filename)

        # 1. Dangerous / Executable Extension Check
        if ext in DANGEROUS_EXTENSIONS:
            has_executable = True
            flagged.append(
                FlaggedAttachment(
                    filename=filename,
                    sha256=att.sha256,
                    extension=ext,
                    claimed_mime=claimed_mime,
                    reason=f"Dangerous executable/script extension detected: {ext}",
                )
            )

        # 2. Double Extension Check
        if DOUBLE_EXTENSION_PATTERN.search(filename.lower()):
            has_double_ext = True
            flagged.append(
                FlaggedAttachment(
                    filename=filename,
                    sha256=att.sha256,
                    extension=ext,
                    claimed_mime=claimed_mime,
                    reason=f"Double extension evasion technique detected: {filename}",
                )
            )

        # 3. MIME Mismatch Check
        # Case A: Document/image extension but executable MIME
        if ext in {".pdf", ".docx", ".xlsx", ".jpg", ".png", ".txt"} and claimed_mime in EXECUTABLE_MIMES:
            has_mime_mismatch = True
            flagged.append(
                FlaggedAttachment(
                    filename=filename,
                    sha256=att.sha256,
                    extension=ext,
                    claimed_mime=claimed_mime,
                    reason=f"MIME mismatch: File extension '{ext}' claims executable MIME type '{claimed_mime}'",
                )
            )
        # Case B: Executable extension but claims to be a benign document/image
        elif ext in DANGEROUS_EXTENSIONS and claimed_mime in DOCUMENT_MIMES:
            has_mime_mismatch = True
            flagged.append(
                FlaggedAttachment(
                    filename=filename,
                    sha256=att.sha256,
                    extension=ext,
                    claimed_mime=claimed_mime,
                    reason=f"MIME spoofing: Dangerous executable extension '{ext}' disguised as benign MIME '{claimed_mime}'",
                )
            )

    return AttachmentAnalysisResult(
        total_attachments_inspected=len(attachments),
        has_executable_attachment=has_executable,
        has_double_extension=has_double_ext,
        has_mime_mismatch=has_mime_mismatch,
        flagged_attachments=flagged,
        html_attachments=html_files,
    )
