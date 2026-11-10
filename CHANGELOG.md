# Changelog

All notable changes to oscore-nv are recorded here. The format is
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
with the pre-1.0 rule that a breaking change bumps the MINOR number.

## 0.1.0

The first release.

### Added

- **`oscctx`**, the security context of RFC 8613 section 3: `derive` from a master
  secret, salt, Sender ID, Recipient ID and ID Context by HKDF-SHA-256; the AEAD
  nonce of section 5.2; the Partial IV and the Sender Sequence Number, with the
  procedure of Appendix B.1.1 (`ssn_needs_store`, `ssn_restore`); the replay window
  of 32 of section 7.4, with the lower limit of Appendix B.1.2 (`replay_floor`);
  and `recipient_matches`.
- **`oscopt`**, the OSCORE option value of section 6.1, written and read, and the
  reading and writing of CoAP options on a message or a plaintext.
- **`oscmsg`**, `protect_request`, `unprotect_request`, `protect_response` and
  `unprotect_response` over the CoAP messages of coap-nv: the option classes of
  section 4, the Outer Code, the additional data of section 5.4, the Observe
  rules of sections 4.1.3.5 and 8.4.2, the guard against using a nonce twice, and
  `error_code` for the response a server may send to a message it refuses.
- **`oscccm`**, AES-CCM-16-64-128 of RFC 3610 in place, over crypto-nv's AES.
- **`osckdf`**, SHA-256, HMAC-SHA-256 and HKDF-SHA-256 over buffers of fixed size.
- **`tests/embedded_probe.nv`**, a firmware program for a gateway test rig, built
  for `--target=nrf52-qemu`. It prints `PASS: oscore-embedded` under QEMU. The image
  is 56,988 bytes of flash and 528 bytes of static RAM.
- Six test suites: RFC 8613 appendix C cut out of the RFC's text, the packet
  vectors of RFC 3610 with a 13-byte nonce and an 8-byte tag, the encrypted CWT of
  RFC 8392 appendix A.5, the HMAC vectors of RFC 4231 and the HKDF vectors of
  RFC 5869.

### Not included

- Algorithms other than AES-CCM-16-64-128 and HKDF-SHA-256.
- Proxy-Uri (RFC 8613 section 4.1.3.3), Outer Block options (section 4.1.3.4.2),
  nested OSCORE, Class I options and signaling messages.
- Group OSCORE, key establishment, Appendix B.2, the Echo exchange of Appendix B.1.2,
  and a replay window other than 32.

### Known

- A message and a plaintext are the 1,152 bytes of coap-nv's `CoapMsg`, so a payload
  over about 1,130 bytes is refused with `OSC_E_NOSPACE`; larger bodies go in blocks.

This release requires novo 0.23.0 or later.
