import re
from typing import List
from backend.app.schemas.forensic import ForensicEmail
from backend.app.schemas.threat import SecuritySignal, SignalCategory, SignalSeverity

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".ps1", ".js", ".hta", ".iso", ".img", ".wsf", ".jar", ".com"
}
MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}
DOUBLE_EXT_REGEX = re.compile(r"\.(?:pdf|docx?|xlsx?|png|jpg|txt)\.(?:exe|scr|vbs|bat|js|ps1|hta|iso)$", re.I)


def evaluate_attachment_rules(forensic: ForensicEmail) -> List[SecuritySignal]:
    """Evaluate attachment characteristics, extensions, and metadata anomalies."""
    signals: List[SecuritySignal] = []

    for att in forensic.attachments:
        fname = att.filename.lower().strip()

        # 1. Double Extension Cloaking
        if DOUBLE_EXT_REGEX.search(fname):
            signals.append(
                SecuritySignal(
                    id="SIG-ATT-DBLEXT-01",
                    type="DOUBLE_EXTENSION",
                    category=SignalCategory.ATTACHMENT,
                    severity=SignalSeverity.CRITICAL,
                    score_contribution=40,
                    title="Dangerous Double-Extension Cloaking",
                    description=f"Attachment '{att.filename}' uses a deceptive double file extension to masquerade an executable payload as a document.",
                    evidence_references=[f"Attachment: {att.filename} ({att.content_type})"],
                    confidence=0.98,
                )
            )

        # 2. Direct Executable / Script Extension
        file_ext = "." + fname.rsplit(".", 1)[-1] if "." in fname else ""
        if file_ext in EXECUTABLE_EXTENSIONS:
            signals.append(
                SecuritySignal(
                    id="SIG-ATT-EXEC-01",
                    type="EXECUTABLE_EXTENSION",
                    category=SignalCategory.ATTACHMENT,
                    severity=SignalSeverity.CRITICAL,
                    score_contribution=35,
                    title="Direct Executable / Script File Attached",
                    description=f"Attachment '{att.filename}' is an executable or script format capable of direct system payload execution.",
                    evidence_references=[f"Attachment: {att.filename} ({att.content_type})"],
                    confidence=0.95,
                )
            )

        # 3. Macro-Enabled Document
        if file_ext in MACRO_EXTENSIONS:
            signals.append(
                SecuritySignal(
                    id="SIG-ATT-MACRO-01",
                    type="MACRO_ENABLED_DOCUMENT",
                    category=SignalCategory.ATTACHMENT,
                    severity=SignalSeverity.HIGH,
                    score_contribution=25,
                    title="Macro-Enabled Office Document",
                    description=f"Attachment '{att.filename}' supports embedded VBA macro code, a frequent vector for dropper delivery.",
                    evidence_references=[f"Attachment: {att.filename} ({att.content_type})"],
                    confidence=0.90,
                )
            )

    return signals
