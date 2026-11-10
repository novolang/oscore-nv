# oscore-nv

CoAP is HTTP for devices that cannot afford HTTP, and the way it is usually
secured, DTLS, protects a connection: the traffic is encrypted between two
hops, and every proxy and gateway on the path sees all of it. OSCORE, Object
Security for Constrained RESTful Environments
([RFC 8613](https://www.rfc-editor.org/rfc/rfc8613)), protects the messages
themselves: a request and its response are encrypted and authenticated from
the endpoint that made them to the endpoint that reads them, whatever carries
them in between. This package brings it to novo-lang for a device with no heap.

## What it is

A sensor behind a gateway sends `GET /temperature`. The gateway, a proxy and a
cache all have to be able to route and forward the message, so a few fields stay
in the clear: the message type, the ID and token, and the options that name where
the request goes. Everything that says what it is, the method, the path, the
query and the payload, is encrypted and authenticated, and goes in the payload of
a message that is a `POST` to nowhere in particular. OSCORE is the rules for the
split and the cryptography that holds it together.

The package has no socket and no clock. It takes a CoAP message in a buffer the
caller owns and writes another, and the other direction. The two ends hold a
**security context** derived from a shared master secret, and the package keeps
the parts of it that change: the sequence number that makes every nonce new, and
the window that refuses a request it has seen.

**Nothing is allocated.** A message is the `Vec[u8; 1152]` of
[coap-nv](https://novo-lang.org/packages/coap-nv). The security context is 192
bytes. The AEAD, AES-CCM-16-64-128, and the HMAC-SHA-256 under the key
derivation are in the package, over crypto-nv's block cipher and compression
function, and they build for a Cortex-M with the rest.

## Install

```
novo pkg add oscore-nv
```

## Example

A client and a server are given the same master secret. The client protects a
request, the server verifies it and answers, and the client verifies the answer.
The master secret and the request are those of RFC 8613 appendix C.

```novo
use oscctx
use oscmsg

// The master secret 01..10 and the master salt of RFC 8613 appendix C.1.
fn contexts(var client: OscoreCtx, var server: OscoreCtx)
    var secret: Vec[u8; 256] = Vec.new()
    for i in 1..17
        let _a = secret.push(i as u8)
    var salt: Vec[u8; 256] = Vec.new()
    for b in [0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40]
        let _b = salt.push(b as u8)
    var none: Vec[u8; 256] = Vec.new()
    // The client's Sender ID is empty and its Recipient ID 01; the server the other way round.
    let _c = oscctx.derive(var client, var secret, 16, var salt, 8, 0, 0, 1, 1, var none, -1)
    let _d = oscctx.derive(var server, var secret, 16, var salt, 8, 1, 1, 0, 0, var none, -1)

fn main() [io]
    var client = oscctx.new_ctx()
    var server = oscctx.new_ctx()
    contexts(var client, var server)

    // A CoAP GET for /tv1 on host "localhost": 44 01 5d1f 00003974 | 39 localhost | 83 tv1.
    var request: Vec[u8; 1152] = Vec.new()
    for b in [0x44, 0x01, 0x5d, 0x1f, 0x00, 0x00, 0x39, 0x74, 0x39, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x68, 0x6f, 0x73,
              0x74, 0x83, 0x74, 0x76, 0x31]
        let _e = request.push(b as u8)

    // The client protects it.  What goes on the wire is a POST with the OSCORE option.
    var wire: Vec[u8; 1152] = Vec.new()
    var client_note = oscmsg.new_req()
    let a = oscmsg.protect_request(var client, var request, var wire, var client_note)
    println("protected: ${a}, ${wire.len()} bytes, code ${wire[1]}")   // protected: 0, 35 bytes, code 2

    // The server verifies it and finds the original.
    var seen: Vec[u8; 1152] = Vec.new()
    var server_note = oscmsg.new_req()
    let b = oscmsg.unprotect_request(var server, var wire, var seen, var server_note)
    println("verified: ${b}, code ${seen[1]}, ${seen.len()} bytes")   // verified: 0, code 1, 22 bytes

    // The same message again is a replay.
    var again: Vec[u8; 1152] = Vec.new()
    let c = oscmsg.unprotect_request(var server, var wire, var again, var server_note)
    println("second time: ${c}")   // second time: 9
```

Build and test with `novo pkg build` and `novo test tests --isolate`.

## What the package contains

| Module | Contents |
| --- | --- |
| `oscctx` | The security context: `derive` from a master secret by the HKDF of section 3.2, the AEAD nonce of section 5.2, the Partial IV and the Sender Sequence Number with the persistence procedure of Appendix B.1.1, and the replay window of section 7.4. |
| `oscopt` | The OSCORE option: the compressed COSE object of section 6, written and read, and the reading and writing of CoAP options that the protection needs. |
| `oscmsg` | `protect_request`, `unprotect_request`, `protect_response`, `unprotect_response` for CoAP messages of coap-nv: the option classes, the Outer Code, the additional data, the Observe rules. |
| `oscccm` | AES-CCM-16-64-128 of RFC 3610, in place, with a 13-byte nonce and an 8-byte tag. |
| `osckdf` | SHA-256, HMAC-SHA-256 and HKDF-SHA-256 over buffers of fixed size. |

Every `pub` declaration is documented where it is declared, and
[the package's page](https://novo-lang.org/packages/oscore-nv) is that
reference.

## The rules a user needs

1. **A context is derived once and kept in RAM.** `derive` takes the master
   secret and salt, the two IDs and the ID Context, and keeps the keys and the
   Common IV, 45 bytes. The master secret is not kept. A Sender ID and Recipient
   ID are at most 7 bytes; the empty one is valid.
2. **The sequence number must never repeat.** It starts at 0 and every request
   and every response with a new Partial IV takes the next. If the RAM holding it
   can be lost, use the procedure of Appendix B.1.1: `ssn_needs_store` says when
   to write the number to non-volatile memory, and after a reboot `ssn_restore`
   starts at the stored number plus an interval K and a margin F. At 2^40 - 1 the
   context stops sending: `protect_*` answers `OSC_E_SSN`.
3. **The caller finds the context.** A server holds one context per client and
   picks the one whose Recipient ID is the request's `kid`, and whose ID Context
   is its `kid context` if there is one. `oscctx.recipient_matches` is that test.
   `unprotect_request` checks it again and answers `OSC_E_NO_CONTEXT`.
4. **A request is checked in this order:** the option decodes, the context
   matches, the Partial IV is not in the replay window, the tag verifies. Only a
   verified request moves the window. A server may answer a failure with the code
   `error_code` gives; the response is a plain CoAP message, not protected.
5. **Options are split by class.** Uri-Host, Uri-Port and Proxy-Scheme stay
   outside. Observe is both: its value goes inside and a copy stays outside.
   Everything else, the method, Uri-Path, Uri-Query, Content-Format, ETag,
   Max-Age, Block1, Block2, Size, No-Response, any option this package does not
   know, and the payload, is encrypted. When a message is verified, the outer
   options that are not Class U are dropped and the decrypted ones replace them.
6. **A response is bound to its request.** `unprotect_response` and
   `protect_response` take the `OscoreReq` that the request left. A response
   verifies only as the answer to the request whose `kid` and Partial IV went into
   its additional data.
7. **A nonce is used once.** A response without a Partial IV of its own reuses the
   nonce of the request, once. `protect_response` refuses a second one with
   `OSC_E_NONCE_REUSE`, and so does `unprotect_response`. Pass `new_piv` true for
   the next response to the same request.
8. **Observe.** A registration (Observe 0) goes out with the Outer Code FETCH. The
   first notification may reuse the request's nonce; every later one carries a
   Partial IV, and the client accepts one only if its Partial IV is higher than the
   last it verified. The verified notification has its Observe value set to the low
   24 bits of the Partial IV.
9. **Failures are values.** Each status is a constant: a message that does not
   parse, an OSCORE option that does not decode, a context not found, a replay, a
   tag that does not verify, a result that does not fit. A failed verification
   leaves the replay window and the request record as they were.
10. **The tag is compared in full.** `oscccm.open` accumulates the difference of
    every byte of the tag before it decides, and on a failure empties the message,
    so no plaintext of a message that did not verify is left behind. The package
    makes no other claim about timing; the AES under it is crypto-nv's, and that
    package says what it claims.

## Running on a microcontroller

All five modules are `@tier(embedded)` and `@no_alloc` throughout, and the package
declares no effects. `tests/embedded_probe.nv` is a firmware program for a gateway
test rig. It derives the client's and the server's contexts from the master secret
of RFC 8613 appendix C.1, protects the GET request of C.4 and checks the bytes
against the RFC's, verifies it and refuses a copy as a replay, protects the
response of C.7, and verifies that. It is compiled for a Cortex-M as part of this
package's checks, so the claim is built rather than asserted, and under QEMU it
prints `PASS: oscore-embedded`.

The image is 56,988 bytes of flash and 528 bytes of static RAM, including the
runtime and the board's startup code. The program's own code is 42,860 bytes of
that flash, of which coap-nv's message code is a part. The probe's frame holds six
message buffers of 1,160 bytes, and a protection or a verification uses one more
of 1,160 bytes for the plaintext and the ciphertext, and an expanded AES key of
496 bytes.

The device effects are the caller's. The package reads no register and no clock,
and draws no random numbers; the nonce is a counter.

## What is not included

- **Algorithms other than AES-CCM-16-64-128 and HKDF-SHA-256.** RFC 8613 makes
  these the ones that must be implemented. ChaCha20/Poly1305 and the other HKDF
  hashes are not here.
- **Proxy-Uri.** Splitting it into the outer Proxy-Scheme, Uri-Host and Uri-Port
  and the inner Uri-Path (section 4.1.3.3) is not implemented; a message that has
  one is refused with `OSC_E_UNSUPPORTED`.
- **Outer Block options.** Block1, Block2, Size1 and Size2 of the original message
  are encrypted with it, so a message is divided into blocks before it is
  protected (coap-nv's `coapblock`). The Block options a proxy adds around an
  OSCORE message (section 4.1.3.4.2) are not handled: the caller reassembles the
  outer blocks into one message before verifying it, and applies its own limit on
  the size.
- **Nested OSCORE** (a message that already has an OSCORE option) and **Class I
  options**, of which none is defined.
- **Signaling messages** over a reliable transport (section 4.3).
- **Group OSCORE** and the key establishment that gives two endpoints a master
  secret. The master secret is an argument.
- **Appendix B.2**, deriving a new context from the old one with fresh randomness.
  The ID Context is the hook for it; the exchange is not here.
- **Echo** (Appendix B.1.2). `replay_floor` is the lower limit it sets; the Echo
  option and the exchange are not.
- **A replay window other than 32.**
- **A transport.** The CoAP messaging layer, retransmission and the matching of a
  response to a request by token are coap-nv's and the caller's.

## Related packages

- [coap-nv](https://novo-lang.org/packages/coap-nv) is the CoAP message this
  package reads and writes, and its message layer, block-wise transfer and observe
  state are what an OSCORE endpoint runs around it.
- [cose-nv](https://novo-lang.org/packages/cose-nv) is the general COSE; OSCORE
  uses a compressed COSE_Encrypt0 and writes it itself.
- [crypto-nv](https://novo-lang.org/packages/crypto-nv) supplies the AES block
  cipher and the SHA-256 compression function that `oscccm` and `osckdf` are
  written over.

## Tests

The suite is six files under `tests/`. What they assert comes from the RFCs
rather than from an implementation.

`tests/oscore_rfc8613_tests.nv` holds appendix C of RFC 8613, cut out of the RFC's
text by `tests/generate/gen_oscore_vectors.py`: the three key derivations for the
client and the server, with the info strings, the keys, the Common IV and the
nonces; the GET request of C.4, C.5 and C.6, protected at sequence number 20 and
compared with the RFC's bytes, then verified by the other end and refused when it
arrives a second time; and the responses of C.7 and C.8.

`tests/oscccm_tests.nv` holds the 12 packet vectors of RFC 3610 that use a 13-byte
nonce and an 8-byte tag, and opens the encrypted CWT of RFC 8392 appendix A.5,
which is the same algorithm under COSE number 10.

`tests/osckdf_tests.nv` holds the HMAC-SHA-256 vectors of RFC 4231, the HKDF
vectors of RFC 5869, and SHA-256 at the lengths where its padding changes, whose
digests were computed with Python's `hashlib`.

`tests/oscore_edge_tests.nv` holds the five option values of RFC 8613 section 6.3,
the additional data of section 5.4, the replay window and the sequence number at
their edges, and the context's refusals.

`tests/oscore_protect_tests.nv` splits requests by option class, verifies a message
with an outer ETag, runs an Observe registration and its notifications, and
refuses every kind of bad message, including those whose tag is right and whose
plaintext is not.

`tests/embedded_probe.nv` is the microcontroller program described above.

## Licence

Apache-2.0. See `LICENSE`.
