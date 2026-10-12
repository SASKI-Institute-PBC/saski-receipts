"""Check the published receipt vectors.

The only dependency outside the Python standard library is the
cryptography package. Keys and secrets in the vector files are TEST ONLY.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import sys
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_QUANTUM = Decimal("0.00000001")

# Receipt version 1.3. The signature covers these names when they are present.
# ``signature`` itself is not in this list.
_RECEIPT_FIELDS = (
    "receipt_id",
    "receipt_version",
    "alg",
    "kid",
    "agent_id",
    "parent_agent_id",
    "parent_receipt_id",
    "tool_name",
    "resource",
    "parameters_digest",
    "requested_parameters_digest",
    "modification_record",
    "policy_version",
    "rulebook_digest",
    "rulebook_template_id",
    "rulebook_vertical",
    "risk_level",
    "config_provenance",
    "verdict",
    "reason_codes",
    "prerequisite_attribution",
    "origin_event_id",
    "human_id",
    "workflow_id",
    "session_id",
    "hop_index",
    "prev_receipt_id",
    "human_decision",
    "hold_id",
    "timestamp",
    "timestamp_ns",
    "gateway_code_digest",
    "gateway_build_ref",
    "gateway_instance_id",
    "tenant_id",
    "community_id",
    "is_emulator",
    "engine_status",
    "connection_event",
    "connection_id",
    "prev_connection_id",
    "downstream_host",
    "downstream_port",
    "operator_text_digest",
    "assistant_text_digest",
    "chain_id",
    "commitment_mode",
    "commitment_key_id",
    "record_type",
    "product",
    "emitted_profiles",
    "time_window_id",
    "time_window_seconds",
    "encoder_id",
    "record_flags",
    "product_version",
    "network_policy_hash",
    "coverage",
    "old_profiles",
    "new_profiles",
    "config_source",
    "core_record_id",
    "core_hash",
)

# Decision record version 1.3. HMAC and Ed25519 cover the same names.
# ``signature`` and ``attestation_hash`` are not in this list.
_DECISION_FIELDS = (
    "attestation_version",
    "timestamp_utc",
    "conversation_id",
    "run_id",
    "sdk_version",
    "policy_hash",
    "necessity_matrix_version",
    "message_for_llm_hash",
    "decision_hash",
    "signature_alg",
    "tenant_id",
    "sdk_instance_id",
    "sdk_code_digest",
    "prev_attestation_hash",
    "rules_fingerprint",
    "reason_fingerprint",
    "direction",
    "input_commitment",
    "commitment_mode",
    "commitment_key_id",
    "timestamp_ns",
    "sequence",
    "record_type",
    "product",
    "emitted_profiles",
    "time_window_id",
    "time_window_seconds",
    "encoder_id",
    "record_flags",
)
_DECISION_OPTIONAL = (
    "policy_id",
    "policy_version",
    "network_policy_hash",
    "build_ref",
    "output_commitment",
    "coverage",
    "old_profiles",
    "new_profiles",
    "config_source",
)


class CanonicalError(ValueError):
    """The value cannot be written as canonical JSON."""


def _quantize_float(value: float) -> str:
    if value != value:
        raise CanonicalError("NaN is not allowed")
    if value == float("inf") or value == float("-inf"):
        raise CanonicalError("infinity is not allowed")
    quantized = Decimal(str(value)).quantize(_QUANTUM, rounding=ROUND_HALF_EVEN)
    return str(quantized)


def _canonicalize(value: Any) -> Any:
    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return _quantize_float(value)
    if isinstance(value, dict):
        return {str(key): _canonicalize(item) for key, item in sorted(value.items())}
    if isinstance(value, list):
        return [_canonicalize(item) for item in value]
    raise CanonicalError(f"unsupported value type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """UTF-8 canonical JSON: sorted keys, compact separators, fixed floats."""
    text = json.dumps(
        _canonicalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return text.encode("utf-8")


def _ed25519_ok(public_b64: str, payload: bytes, signature_b64: str) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_b64.encode("ascii")))
        public.verify(base64.b64decode(signature_b64.encode("ascii")), payload)
    except (InvalidSignature, ValueError, TypeError):
        return False
    return True


def _hmac_ok(secret: str, payload: bytes, signature_hex: str) -> bool:
    key = secret.encode("utf-8", errors="replace")
    expected = hmac.new(key, payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature_hex)


def _receipt_payload(receipt: dict[str, Any]) -> dict[str, Any]:
    return {key: receipt[key] for key in _RECEIPT_FIELDS if key in receipt}


def _decision_payload(record: dict[str, Any]) -> dict[str, Any] | None:
    if record.get("attestation_version") != "1.3":
        return None
    names = _DECISION_FIELDS + tuple(key for key in _DECISION_OPTIONAL if key in record)
    if any(key not in record for key in names):
        return None
    return {key: record[key] for key in names}


def _links_hold(receipts: list[dict[str, Any]]) -> bool:
    previous_id = ""
    previous_hop: int | None = None
    for index, receipt in enumerate(receipts):
        linked = str(receipt.get("prev_receipt_id") or "")
        if index == 0:
            if linked:
                return False
        elif linked != previous_id:
            return False
        hop = receipt.get("hop_index")
        if isinstance(hop, bool) or not isinstance(hop, int):
            hop = None
        if previous_hop is not None and hop is not None and hop <= previous_hop:
            return False
        previous_id = str(receipt.get("receipt_id") or "")
        if hop is not None:
            previous_hop = hop
    return True


def _agentic_result(document: dict[str, Any]) -> tuple[bool, bool]:
    """Return (internally consistent, signatures and links verify)."""
    public = str(document.get("test_only", {}).get("ed25519_public_key_b64") or "")
    items = document.get("receipts")
    if not public or not isinstance(items, list) or not items:
        return False, False
    consistent = True
    verified = True
    receipts: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            return False, False
        receipt = item.get("receipt")
        if not isinstance(receipt, dict):
            return False, False
        receipts.append(receipt)
        if item.get("ed25519_public_key_b64") != public:
            consistent = False
        if item.get("signature") != receipt.get("signature"):
            consistent = False
        payload = _receipt_payload(receipt)
        try:
            raw = canonical_bytes(payload)
        except CanonicalError:
            return False, False
        if raw.decode("utf-8") != item.get("canonical_utf8"):
            consistent = False
        signature = receipt.get("signature")
        if not isinstance(signature, str) or not _ed25519_ok(public, raw, signature):
            verified = False
    if not _links_hold(receipts):
        verified = False
    return consistent, verified and consistent


def _sdk_result(document: dict[str, Any]) -> tuple[bool, bool]:
    """Return (internally consistent, HMAC and Ed25519 verify)."""
    record = document.get("attestation")
    material = document.get("test_only")
    if not isinstance(record, dict) or not isinstance(material, dict):
        return False, False
    payload = _decision_payload(record)
    if payload is None:
        return False, False
    try:
        raw = canonical_bytes(payload)
    except CanonicalError:
        return False, False
    consistent = raw.decode("utf-8") == document.get("canonical_utf8")
    signature = record.get("signature")
    secret = material.get("hmac_secret")
    public = material.get("ed25519_public_key_b64")
    ed_signature = document.get("ed25519_signature")
    block = document.get("ed25519_attestation")
    if not isinstance(signature, str) or not isinstance(secret, str):
        return False, False
    if not isinstance(public, str) or not isinstance(ed_signature, str):
        return False, False
    if document.get("hmac_hex") != signature:
        consistent = False
    if not isinstance(block, dict) or block.get("signature") != ed_signature:
        consistent = False
    verified = _hmac_ok(secret, raw, signature) and _ed25519_ok(public, raw, ed_signature)
    return consistent, verified and consistent


def _expected_success(document: dict[str, Any]) -> bool | None:
    chain = document.get("expected_verify_chain")
    if chain == "pass":
        return True
    if chain == "fail":
        return False
    result = document.get("expected_result")
    if result == "valid":
        return True
    if result == "invalid":
        return False
    return None


def _status(document: dict[str, Any]) -> tuple[bool, str]:
    """Same pass/fail decision as before, with a line a reader can trust.

    True means the file did what it declared. A valid file verified, or a
    tampered file was rejected. False is an unexpected result.
    """
    if "receipts" in document:
        consistent, verified = _agentic_result(document)
        verified_text = "VALID (signature and chain verified)"
    elif "attestation" in document:
        consistent, verified = _sdk_result(document)
        verified_text = "VALID (HMAC and Ed25519 verified)"
    else:
        return False, "ERROR (not a receipt chain or a decision record)"
    expected = _expected_success(document)
    if expected is None:
        return False, "ERROR (file does not say whether it should verify)"
    if not consistent:
        return False, "ERROR (file does not match its own canonical bytes or signatures)"
    if verified is not expected:
        if expected:
            return False, "ERROR (marked valid, but verification failed)"
        return False, "ERROR (marked tampered, but verification succeeded)"
    if expected:
        return True, verified_text
    return True, "REJECTED as expected (tampering detected)"


def check_document(document: dict[str, Any]) -> bool:
    """True when the file matches its own expected pass or fail."""
    return _status(document)[0]


def _summary(count: int, errors: int) -> str:
    if errors == 0:
        return f"All {count} checks behaved as expected."
    if errors == 1:
        return "1 check did not behave as expected."
    return f"{errors} checks did not behave as expected."


def main(argv: list[str] | None = None) -> int:
    """Print one status line per vector file. Exit 1 when any line is ERROR."""
    del argv
    directory = Path(__file__).resolve().parent / "vectors"
    paths = sorted(path for path in directory.glob("*.json") if path.is_file())
    if not paths:
        print("vectors: ERROR (no vector files found)")
        print(_summary(0, 1))
        return 1
    errors = 0
    for path in paths:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(document, dict):
                ok, detail = _status(document)
            else:
                ok, detail = False, "ERROR (file is not a JSON object)"
        except OSError:
            ok, detail = False, "ERROR (file could not be read)"
        except UnicodeError:
            ok, detail = False, "ERROR (file is not UTF-8)"
        except json.JSONDecodeError:
            ok, detail = False, "ERROR (file is not JSON)"
        except CanonicalError:
            ok, detail = False, "ERROR (canonical JSON was rejected)"
        print(f"{path.name}: {detail}")
        if not ok:
            errors += 1
    print(_summary(len(paths), errors))
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
