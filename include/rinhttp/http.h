/* SPDX-License-Identifier: MIT */
#ifndef RINHTTP_HTTP_H
#define RINHTTP_HTTP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIN_HTTP_MAX_DATE_BYTES 64u
#define RIN_HTTP_MAX_RESPONSE_HEADER_BYTES 65536u
#define RIN_HTTP_MAX_BASIC_CREDENTIAL_BYTES 4096u
/* C-string names accepted by the cache-directive compatibility entry point
 * are bounded by the common response-head budget before they are scanned. */
#define RIN_HTTP_MAX_CSTRING_BYTES RIN_HTTP_MAX_RESPONSE_HEADER_BYTES

typedef enum RinHttpStatus {
    RIN_HTTP_OK = 0,
    RIN_HTTP_NOT_FOUND = 1,
    RIN_HTTP_INVALID_ARGUMENT = -1,
    RIN_HTTP_MALFORMED = -2,
    RIN_HTTP_BUFFER_TOO_SMALL = -3,
    RIN_HTTP_OVERFLOW = -4,
    RIN_HTTP_UNSUPPORTED = -5
} RinHttpStatus;

typedef struct RinHttpSlice {
    const uint8_t* data;
    size_t size;
} RinHttpSlice;

typedef struct RinHttpAuthorization {
    RinHttpSlice scheme;
    RinHttpSlice credentials;
} RinHttpAuthorization;

/* Parsed response-head metadata. Header names and values are validated by the
 * common parser; unknown fields are intentionally ignored by this bounded
 * metadata view. */
typedef struct RinHttpResponseHead {
    uint16_t status_code;
    uint8_t has_content_length;
    uint8_t has_transfer_encoding;
    uint8_t transfer_encoding_chunked;
    uint8_t reserved;
    uint64_t content_length;
} RinHttpResponseHead;

/* Validate one HTTP token field name and compare names without ASCII case
 * sensitivity. Both APIs accept exact, non-NUL-terminated slices. */
int rin_http_field_name_valid(const uint8_t* data, size_t size);
int rin_http_field_name_equal(const uint8_t* left, size_t left_size,
                              const uint8_t* right, size_t right_size);

/* Compare two HTTP tokens without ASCII case sensitivity.  Both inputs are
 * exact, non-NUL-terminated slices and must satisfy the RFC token grammar. */
int rin_http_token_equal(const uint8_t* left, size_t left_size,
                         const uint8_t* right, size_t right_size);

/* Validate a comma-separated HTTP token-list field value and report whether
 * the requested token is present. OWS around tokens and commas is accepted;
 * empty members and invalid bytes are rejected. */
int rin_http_field_value_has_token(const uint8_t* data, size_t size,
                                   const uint8_t* token, size_t token_size);

/* Parse one Content-Length field value after optional OWS.  value is cleared
 * before validation, so a failure never leaves a previous length published. */
int rin_http_parse_content_length(const uint8_t* data, size_t size,
                                  uint64_t* value);

/* Validate a comma-separated Transfer-Encoding value. Returns 1 when the
 * final coding is chunked, 0 when it is another valid coding. */
int rin_http_transfer_encoding_final_chunked(const uint8_t* data, size_t size);

/* Validate media type plus parameters and copy its lowercase type/subtype
 * (without parameters) to a NUL-terminated caller buffer.  output is empty
 * and output_size is zero on failure when output has writable capacity. */
int rin_http_normalize_content_type(const uint8_t* data, size_t size,
                                    char* output, size_t output_capacity,
                                    size_t* output_size);

/* Split an Authorization field into its scheme and opaque credentials view.
 * The output view is cleared before validation. */
int rin_http_parse_authorization(const uint8_t* data, size_t size,
                                 RinHttpAuthorization* authorization);

/* Build an RFC 7617 Basic authorization value into a caller-owned buffer.
 * Control bytes and a colon in the username are rejected before Base64
 * encoding. The output is NUL-terminated and output_size excludes it. */
int rin_http_build_basic_authorization(
    const uint8_t* username, size_t username_size,
    const uint8_t* password, size_t password_size, uint8_t* output,
    size_t output_capacity, size_t* output_size);

/* Parse an HTTP response head without its final CRLFCRLF delimiter. The
 * input is bounded to RIN_HTTP_MAX_RESPONSE_HEADER_BYTES, rejects folded or
 * malformed fields, and clears the output on failure. */
int rin_http_parse_response_head(const uint8_t* data, size_t size,
                                 RinHttpResponseHead* output);

/* Parse the IMF-fixdate HTTP-date form into UTC Unix seconds.  The output is
 * cleared before validation. */
int rin_http_parse_imf_fixdate(const uint8_t* data, size_t size,
                               int64_t* unix_seconds);

/* Find one Cache-Control directive. Returns OK when found, NOT_FOUND when
 * absent, and MALFORMED for an invalid directive list. value is empty for a
 * valueless directive and points into the caller-owned input otherwise. name
 * must be NUL-terminated within RIN_HTTP_MAX_CSTRING_BYTES. */
int rin_http_cache_directive_find(const uint8_t* data, size_t size,
                                  const char* name, RinHttpSlice* value);

/* Admit only absolute HTTP(S) redirect targets with an authority and host;
 * userinfo and malformed URI components are rejected. */
int rin_http_redirect_target_valid(const uint8_t* data, size_t size);

#ifdef __cplusplus
}
#endif

#endif /* RINHTTP_HTTP_H */
