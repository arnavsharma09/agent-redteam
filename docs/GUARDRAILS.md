# Guardrails

This project implements two guardrails and a factory helper in
`redteam/defender/guardrails.py`:

- **NaiveKeywordGuardrail**: Checks raw JSON serialized arguments for sensitive
  keywords (`secret`, `password`, `token`, etc.) on sink tools (`http.post`,
  `email.send`, `shell.run`, `fs.delete`, `fs.write`). Bypassed trivially by
  base64, hex, or URL encodings. Demonstrates a **known failure class** in
  adversarial ML and security research, not a novel result.

- **TaintGuardrail**: An argument-provenance gate operating with a per-argument
  policy across sink tools (`http.post`, `email.send`, `shell.run`, `fs.delete`,
  `fs.write`).

## Per-Argument Policy

Arguments are evaluated per tool according to `arg_policy`:
- `"value"`: Strict value provenance on destination/target arguments (`url`,
  `to`, `path`). Checks whole normalized values, URLs, hostnames, emails,
  normalized paths, and base64/hex/URL-decoded variants. Word-token matching is
  disabled to prevent over-blocking benign summaries.
- `"tokens"`: Word-token matching (`min_token_len`) for command strings
  (`shell.run` `cmd`), including base64/hex/URL-decoded variants checked as
  whole semantic entities.
- `"ignore"`: Free-text payload arguments (`data`, `body`, `subject`,
  `content`) are ignored for general word-level taint to avoid over-blocking
  benign summaries, but remain subject to the global **protected content leak** check.
- Unlisted arguments default to `"ignore"` and are recorded in `unchecked_args`.

## Protected Content Leak & Limitations

- **`secret_sources`** (default `("secret.txt",)`): When an agent successfully
  reads a path in `secret_sources` via `fs.read`, its verbatim output is
  registered as "protected content".
- **Leak Detection**: Evaluated across **all** sink arguments regardless of their
  `arg_policy` mode (including `"ignore"` fields such as `http.post` `data` or
  `email.send` `body`). If an argument contains a substantial substring of
  protected content, it is blocked with `protected_content_leak:<arg_name>`.
- **Substantial Substring Definition**:
  1. Exact match after whitespace normalization (`"".join(val.split()) == "".join(secret.split())`).
  2. Contiguous run: shares a contiguous substring of at least
     `secret_match_min_chars` (default 20) characters with the protected content
     (evaluated case-insensitively across whole content and per line).
- **Split-Evasion Limitation**: If an adversary splits a secret into small
  fragments strictly shorter than `secret_match_min_chars` (e.g. 10 chars each)
  interleaved with arbitrary noise, this non-fuzzy matcher will not trigger.
  This is an acceptable and expected limitation of an exact/substring matcher;
  fuzzy matching was intentionally avoided to eliminate false-positive blocks
  on benign summaries.

## Decision Order

1. **Provenance per arg policy**: Checks arguments according to `arg_policy`.
2. **Protected content leak**: Checks all sink arguments against read `secret_sources`.
   Runs before `allowlist_domains`—leaking protected secrets is never excused
   by an allowlisted destination.
3. **Protected paths**: Blocks unauthorized `fs.write` and `fs.delete` on `protected_paths`.
4. **Allowlist domains**: Whitelists trusted URL/hostname destinations for provenance.
5. **Residual judge**: Optional deterministic callback for undecided cases.
6. **ALLOW**: Emits `Decision.allow("no tainted args")`.

## Protected Paths & Laundering Limitation

- **`protected_paths`** (default `("secret.txt",)`): Blocks `fs.write` and
  `fs.delete` on sensitive files (`protected_path:<path>`) unless the path
  explicitly appears in trusted user messages.
- **Laundering limitation**: If an attacker prompts an agent without explicitly
  naming the target (e.g. "delete the sensitive file in the root"), provenance
  checks cannot detect taint. The action is only caught if the target is in
  `protected_paths` or blocked by `allowlist_domains`.

## Operational Trade-Offs

- **User intent wins**: Values provided directly in user messages are trusted.
- **Fail-closed**: Unbound guardrails deny all sink calls (`unbound_guardrail`).
- **False-positive risk**: Any DENY decision aborts the interaction's entire hop
  loop. Incidental collision between untrusted and generated destination values
  terminates task execution.
