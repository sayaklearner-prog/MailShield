import re
from typing import Tuple
from backend.app.schemas.correlation import NodeType


class CorrelationNormalizer:
    """Normalizes entity values into canonical graph node identifiers."""

    @staticmethod
    def normalize_node_id(entity_type: NodeType, raw_value: str) -> str:
        """Create a deterministic, canonical node ID string."""
        clean = raw_value.strip()

        if entity_type == NodeType.EMAIL:
            return f"email:{clean}"

        elif entity_type == NodeType.IP:
            return f"ip:{clean}"

        elif entity_type == NodeType.DOMAIN:
            # Strip protocol and leading www if present, lowercase
            dom = clean.lower()
            dom = re.sub(r"^https?://", "", dom)
            dom = dom.split("/")[0]
            if dom.startswith("www."):
                dom = dom[4:]
            return f"domain:{dom}"

        elif entity_type == NodeType.URL:
            return f"url:{clean}"

        elif entity_type == NodeType.EMAIL_ADDRESS:
            addr = clean.lower()
            if "<" in addr and ">" in addr:
                match = re.search(r"<([^>]+)>", addr)
                if match:
                    addr = match.group(1).strip()
            return f"email_address:{addr}"

        elif entity_type == NodeType.ATTACHMENT:
            return f"attachment:{clean.lower()}"

        elif entity_type == NodeType.ASN:
            raw_as = clean.upper()
            if not raw_as.startswith("AS") and raw_as.isdigit():
                raw_as = f"AS{raw_as}"
            return f"asn:{raw_as}"

        elif entity_type == NodeType.INVESTIGATION:
            return f"investigation:{clean}"

        return f"entity:{clean}"

    @staticmethod
    def parse_node_id(node_id: str) -> Tuple[NodeType, str]:
        """Parse node id into (NodeType, normalized_value)."""
        parts = node_id.split(":", 1)
        if len(parts) == 2:
            try:
                nt = NodeType(parts[0])
                return nt, parts[1]
            except ValueError:
                pass
        return NodeType.EMAIL, node_id
