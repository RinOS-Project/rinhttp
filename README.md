# RinHTTP

Validates and parses bounded HTTP header fields, response heads, metadata, authorization values, dates, and redirect targets.

## Public API contract

| Requirement | Contract |
| --- | --- |
| Purpose | Validates and parses bounded HTTP header fields, response heads, metadata, authorization values, dates, and redirect targets. |
| Supported API | include/rinhttp/http.h: counted-byte parsing and normalization helpers. |
| Unsupported API | Not a socket client/server, TLS layer, full HTTP stack, or credential store. |
| ownership | Input slices are borrowed per call; caller owns outputs and any resulting storage. |
| thread-safety | Stateless helpers may run concurrently with disjoint buffers. |
| limits | Response-header budget 65,536 bytes, Basic credentials 4096 bytes, HTTP date 64 bytes. |
| errors | RinHttpStatus distinguishes malformed, short-buffer, overflow, unsupported syntax, and not-found. Content-Type and Transfer-Encoding parameters require the RFC `name=value` form; invalid or overflowed input fails closed with cleared caller output. Authorization parsing publishes scheme and credentials views only after the complete field is valid. |
| ABI stability | Public C declarations are source ABI; no separate binary ABI version. |
| security | Parsing does not authenticate TLS, authorize redirects, or grant network access; callers enforce those policies. |
| build | No standalone build file; compile http.c with RinEncoding and RinURI through a consumer build. |
| test | No standalone test target; parent CI exercises parser contracts through `tests/rinhttp_test.c` with strict C11/Werror. |
