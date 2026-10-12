# SASKI receipts

A SASKI receipt is a signed record of one decision. It says who acted, what was attempted, which rules were in force, and what was decided. It stores fingerprints, not private content: no message text, no tool arguments, and no names of people.

This directory is a practice package. Every key, seed, and secret in it is **TEST ONLY**. Those values are for checking these files. They are not production keys and must not be used to protect anything real.

Two products are included:

- An **Agentic** receipt chain. Each hop is an Ed25519 signature over one receipt. The second receipt names the first.
- An **SDK** decision record. HMAC-SHA256 and Ed25519 cover the same canonical bytes. The two products use different TEST ONLY signing keys.

## What the files are

| File | What it is |
|---|---|
| `vectors/agentic_chain_v1_3.json` | Two Agentic receipts. Expected result: the chain verifies. |
| `vectors/agentic_chain_v1_3_tampered.json` | The same chain with one byte of the second verdict changed. Expected result: verification fails. |
| `vectors/sdk_decision_v1_3.json` | One SDK decision record, version 1.3. Expected result: both signatures verify. |
| `vectors/sdk_decision_v1_3_tampered.json` | The same record with the first byte of `decision_hash` changed. The signatures are the originals. Expected result: both signatures fail. |
| `samples/receipt-sample.json` | The first Agentic receipt only, signature included. |
| `verify.py` | Checks every file in `vectors/`. |
| `saski-receipt-sample.html` | A one-page picture of the sample receipt. |

Each vector file also carries `test_only`, which holds the practice Ed25519 seed, the practice public key, the practice HMAC secret, and the practice commitment master. All of those are **TEST ONLY**.

`pinned_clock` records the fixed time and the fixed code-digest stand-ins used in these files. `sdk_code_digest` is the letter `e` repeated. `gateway_code_digest` is the letter `f` repeated. They are labels for this package, not a fingerprint of any program.

## Canonical JSON

SASKI signs canonical JSON, not a pretty-printed document and not RFC 8785.

- Object keys are sorted by Unicode code point.
- Arrays keep their order.
- Separators are a comma and a colon, with no spaces: `,` and `:`.
- Text is UTF-8, and non-ASCII characters stay as characters rather than `\\u` escapes.
- A floating-point number is written as a decimal string with exactly 8 digits after the decimal point. Rounding is half to even (`ROUND_HALF_EVEN`). The number `1.0` is signed as the characters `1.00000000`, including the quotes, because it is a string in the signed JSON.
- Integers stay integers. `true`, `false`, and `null` stay themselves.
- NaN and infinity are rejected. Bytes and other types are rejected.

The signature is computed over those UTF-8 bytes. On a receipt, `signature` is attached after signing and is not part of the signed bytes. On an SDK record, `signature` (the HMAC hex) and `attestation_hash` are outside the signed bytes. `signature_alg` is inside them. The Ed25519 signature for an SDK record sits in the sibling object `ed25519_attestation` and covers the same bytes as the HMAC.

## Agentic receipt fields

These are the fields on `samples/receipt-sample.json`. The signature covers every one of them except `signature`.

| Field | What it means |
|---|---|
| `receipt_id` | Identifier of this receipt. |
| `receipt_version` | Format version. These samples are `1.3`. |
| `alg` | Signature algorithm. These samples use `Ed25519`. |
| `kid` | Name of the signing key. The Agentic practice key is `vector-1`. |
| `agent_id` | Which agent made the attempt. |
| `tool_name` | Which tool the agent tried to call. |
| `resource` | Which resource the tool targeted. Empty in the sample. |
| `parameters_digest` | Fingerprint of the tool arguments. The arguments themselves are not stored. |
| `policy_version` | Version of the policy that was applied. |
| `rulebook_digest` | Fingerprint of the rulebook that was in force. |
| `config_provenance` | Short labels for where that configuration came from. |
| `verdict` | The decision: allow, deny, or hold. |
| `reason_codes` | Short codes an auditor can look up. Not a sentence of private text. |
| `origin_event_id` | Identifier of the event that started this hop. Empty in the sample. |
| `workflow_id` | Workflow this chain belongs to. Receipts in one chain share it. |
| `session_id` | Session this decision belongs to. |
| `hop_index` | Position in the chain. The first hop is `0`. The next hop is a larger integer. |
| `prev_receipt_id` | `receipt_id` of the previous hop. Empty on the first hop. |
| `human_decision` | A human approve or deny when one exists. `null` when nobody has decided. |
| `hold_id` | Identifier of a human hold. Empty when there is no hold. |
| `timestamp` | UTC time of the decision. |
| `timestamp_ns` | The same moment, in nanoseconds. |
| `gateway_code_digest` | Stand-in fingerprint of the gateway build. In this package it is the fixed TEST ONLY value, not a hash of a program. |
| `gateway_instance_id` | Which gateway process wrote the receipt. |
| `commitment_mode` | How commitment fingerprints are derived. These samples use `hkdf`. |
| `commitment_key_id` | Identifier of the commitment key. Not the key, and not the master secret. |
| `record_type` | Kind of record. These samples are `decision`. |
| `product` | Which product signed it. `agentic` on these receipts. |
| `product_version` | Version string of that product. |
| `emitted_profiles` | Which receipt profiles were attached. |
| `time_window_seconds` | Length of the time window, in seconds. The sample uses 300. |
| `time_window_id` | Which window `timestamp_ns` falls in. |
| `encoder_id` | Fingerprint of the canonical JSON rules used to sign. |
| `record_flags` | Record-keeping flags. The sample says the record was written at the time of the decision. |
| `signature` | Ed25519 signature, standard base64, over the canonical bytes of the other fields. |

A chain verifies only when every signature is valid, the first `prev_receipt_id` is empty, each later `prev_receipt_id` equals the previous `receipt_id`, and each `hop_index` is greater than the one before it.

## SDK decision-record fields

The record is `attestation` inside the SDK vector file. HMAC and Ed25519 cover the same fields. `signature` and `attestation_hash` are stored on the record and are not inputs to either signature.

| Field | What it means |
|---|---|
| `attestation_version` | Format version. These samples are `1.3`. |
| `timestamp_utc` | UTC time of the decision. |
| `timestamp_ns` | The same moment, in nanoseconds. |
| `conversation_id` | Conversation this decision belongs to. |
| `run_id` | Identifier of this decision. |
| `sdk_version` | Version string of the SDK that signed. |
| `policy_hash` | Fingerprint of the policy configuration. |
| `necessity_matrix_version` | Version of the necessity rules that were applied. |
| `message_for_llm_hash` | Fingerprint of the sanitized text prepared for the model. Not the text. |
| `decision_hash` | Fingerprint of the sanitized decision text. In this package it is not the same value as `message_for_llm_hash`. |
| `signature_alg` | HMAC algorithm name. These samples use `HMAC-SHA256`. This name is inside the signature. |
| `tenant_id` | Tenant the decision was made for. A label, not a secret. |
| `sdk_instance_id` | Which SDK process wrote the record. |
| `sdk_code_digest` | Stand-in fingerprint of the SDK build. In this package it is the fixed TEST ONLY value, not a hash of a program. |
| `prev_attestation_hash` | Link to the previous record. Empty on the first record. |
| `rules_fingerprint` | Fingerprint of the rule identifiers and the coarse evaluation summary. The identifiers are not stored. Non-empty in this package. |
| `reason_fingerprint` | Fingerprint of the rationale and the decision trace. The text is not stored. Non-empty in this package. |
| `direction` | `input` for a decision about a submission, `output` for a decision about a reply. |
| `input_commitment` | Commitment of the sanitized submission under the TEST ONLY commitment master. Not the submission. Non-empty in this package. |
| `commitment_mode` | How that commitment was derived. These samples use `hkdf`. |
| `commitment_key_id` | Identifier of the commitment key. Not the key, and not the master secret. |
| `sequence` | Position of this record in its session. |
| `record_type` | Kind of record. These samples are `decision`. |
| `product` | Which product signed it. `sdk` on this record. |
| `emitted_profiles` | Which receipt profiles were attached. |
| `time_window_id` | Which time window `timestamp_ns` falls in. |
| `time_window_seconds` | Length of that window, in seconds. |
| `encoder_id` | Fingerprint of the canonical JSON rules used to sign. |
| `record_flags` | Record-keeping flags. |
| `signature` | HMAC-SHA256 hex of the canonical signed fields. Outside the signed bytes. |
| `attestation_hash` | A short digest of the signed fields plus the HMAC. Outside the signed bytes. Not the chain link. |

`ed25519_attestation` is a sibling of `attestation`, not a field inside it:

| Field | What it means |
|---|---|
| `alg` | `Ed25519`. |
| `kid` | Name of the SDK practice key. These samples use `sdk-1`. |
| `signature` | Ed25519 signature, standard base64, over the same canonical bytes as the HMAC. |

The SDK practice key is not the Agentic practice key.

## File wrapper fields

| Field | What it means |
|---|---|
| `label` | `TEST ONLY` on every file in this package. |
| `vector` | Which example this file is. |
| `expected_result` | `valid` or `invalid` for one record. |
| `expected_verify_chain` | `pass` or `fail` for an Agentic chain. |
| `expected_hmac` / `expected_ed25519` | On the tampered SDK file, both are `invalid`. |
| `tamper` | A sentence describing the one-byte change. |
| `chain_key` | Workflow name used to group the Agentic chain. |
| `commitment_mode` | `hkdf` for these files. |
| `canonical_utf8` | The signed canonical JSON as text. |
| `canonical_hex` | Those same bytes in hexadecimal. |
| `sha256` | SHA-256 of those bytes. |
| `hmac_hex` | The HMAC hex. On the tampered SDK file this is still the original. |
| `ed25519_signature` | The Ed25519 signature. On the tampered SDK file this is still the original. |
| `test_only` | Practice seeds, keys, the HMAC secret, and the commitment master. **TEST ONLY.** |
| `pinned_clock` | The fixed time and the fixed code-digest stand-ins. |
| `receipts` | The Agentic hops. Each hop repeats the public key, the canonical bytes, and the receipt. |

## Check the files

From this directory, with Python and the `cryptography` package:

```bash
python verify.py
```

The command prints one line per file in `vectors/`, then one summary line:

```
agentic_chain_v1_3.json: VALID (signature and chain verified)
agentic_chain_v1_3_tampered.json: REJECTED as expected (tampering detected)
sdk_decision_v1_3.json: VALID (HMAC and Ed25519 verified)
sdk_decision_v1_3_tampered.json: REJECTED as expected (tampering detected)
All 4 checks behaved as expected.
```

`VALID` means a file marked valid verified. An Agentic line names the signature and the chain. An SDK line names HMAC and Ed25519, because that record is not a chain. `REJECTED as expected` means a file marked tampered was rejected. `ERROR` means something unexpected happened, and the parentheses say what. The process exits 0 when every file is `VALID` or `REJECTED as expected`, and exits 1 when any line is `ERROR`.

`saski-receipt-sample.html` shows the same receipt as `samples/receipt-sample.json`. The shortened fingerprints on the page are the start and end of the full values in that file. The embedded JSON is that file, unchanged.
