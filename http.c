/* SPDX-License-Identifier: MIT */
#include "include/rinhttp/http.h"

#include "../rinencoding/include/rinencoding/encoding.h"
#include "../rinuri/include/rinuri/uri.h"

#include <string.h>

static int http_ows(uint8_t value)
{
    return value == ' ' || value == '\t';
}

static int http_tchar(uint8_t value)
{
    if ((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
        (value >= '0' && value <= '9')) return 1;
    switch (value) {
        case '!': case '#': case '$': case '%': case '&': case '\'':
        case '*': case '+': case '-': case '.': case '^': case '_':
        case '`': case '|': case '~': return 1;
        default: return 0;
    }
}

static uint8_t http_lower(uint8_t value)
{
    return value >= 'A' && value <= 'Z'
        ? (uint8_t)(value + ('a' - 'A')) : value;
}

static size_t http_trim_begin(const uint8_t* data, size_t size)
{
    size_t offset = 0u;
    while (offset < size && http_ows(data[offset])) ++offset;
    return offset;
}

static size_t http_trim_end(const uint8_t* data, size_t begin, size_t size)
{
    while (size > begin && http_ows(data[size - 1u])) --size;
    return size;
}

static int http_slice_literal(RinHttpSlice slice, const char* literal)
{
    size_t length = 0u;
    size_t index;
    while (literal[length] != '\0') ++length;
    if (slice.size != length) return 0;
    for (index = 0u; index < length; ++index)
        if (http_lower(slice.data[index]) != http_lower((uint8_t)literal[index]))
            return 0;
    return 1;
}

int rin_http_field_name_valid(const uint8_t* data, size_t size)
{
    size_t index;
    if (data == NULL || size == 0u) return RIN_HTTP_MALFORMED;
    for (index = 0u; index < size; ++index)
        if (!http_tchar(data[index])) return RIN_HTTP_MALFORMED;
    return RIN_HTTP_OK;
}

int rin_http_field_name_equal(const uint8_t* left, size_t left_size,
                              const uint8_t* right, size_t right_size)
{
    size_t index;
    if (left_size != right_size ||
        rin_http_field_name_valid(left, left_size) != RIN_HTTP_OK ||
        rin_http_field_name_valid(right, right_size) != RIN_HTTP_OK)
        return 0;
    for (index = 0u; index < left_size; ++index)
        if (http_lower(left[index]) != http_lower(right[index])) return 0;
    return 1;
}

int rin_http_token_equal(const uint8_t* left, size_t left_size,
                         const uint8_t* right, size_t right_size)
{
    size_t index;
    if (left_size != right_size || left == NULL || right == NULL ||
        left_size == 0u)
        return 0;
    for (index = 0u; index < left_size; ++index)
        if (!http_tchar(left[index]) || !http_tchar(right[index]) ||
            http_lower(left[index]) != http_lower(right[index]))
            return 0;
    return 1;
}

int rin_http_field_value_has_token(const uint8_t* data, size_t size,
                                   const uint8_t* token, size_t token_size)
{
    size_t cursor = 0u;
    int found = RIN_HTTP_NOT_FOUND;
    if (token == NULL || token_size == 0u ||
        rin_http_field_name_valid(token, token_size) != RIN_HTTP_OK)
        return RIN_HTTP_INVALID_ARGUMENT;
    if (size != 0u && data == NULL) return RIN_HTTP_INVALID_ARGUMENT;
    if (size == 0u) return RIN_HTTP_MALFORMED;
    for (;;) {
        size_t token_start;
        while (cursor < size && http_ows(data[cursor])) ++cursor;
        token_start = cursor;
        while (cursor < size && http_tchar(data[cursor])) ++cursor;
        if (cursor == token_start) return RIN_HTTP_MALFORMED;
        if (rin_http_token_equal(data + token_start, cursor - token_start,
                                 token, token_size))
            found = RIN_HTTP_OK;
        while (cursor < size && http_ows(data[cursor])) ++cursor;
        if (cursor == size) return found;
        if (data[cursor++] != ',') return RIN_HTTP_MALFORMED;
        if (cursor == size) return RIN_HTTP_MALFORMED;
    }
}

int rin_http_parse_content_length(const uint8_t* data, size_t size,
                                  uint64_t* value)
{
    size_t begin;
    size_t end;
    size_t index;
    uint64_t parsed = 0u;
    if (value == NULL || (size != 0u && data == NULL))
        return RIN_HTTP_INVALID_ARGUMENT;
    begin = http_trim_begin(data, size);
    end = http_trim_end(data, begin, size);
    if (begin == end) return RIN_HTTP_MALFORMED;
    for (index = begin; index < end; ++index) {
        uint8_t digit;
        if (data[index] < '0' || data[index] > '9') return RIN_HTTP_MALFORMED;
        digit = (uint8_t)(data[index] - '0');
        if (parsed > (UINT64_MAX - digit) / 10u) return RIN_HTTP_OVERFLOW;
        parsed = parsed * 10u + digit;
    }
    *value = parsed;
    return RIN_HTTP_OK;
}

static int http_quoted_valid(const uint8_t* data, size_t size, size_t* offset)
{
    size_t cursor = *offset;
    if (cursor >= size || data[cursor] != '"') return 0;
    ++cursor;
    while (cursor < size && data[cursor] != '"') {
        uint8_t value = data[cursor++];
        if (value == '\\') {
            if (cursor >= size || data[cursor] == '\r' || data[cursor] == '\n')
                return 0;
            ++cursor;
        } else if (value < 0x20u || value == 0x7fu || value == '\r' ||
                   value == '\n') return 0;
    }
    if (cursor >= size) return 0;
    *offset = cursor + 1u;
    return 1;
}

static int http_parameter_list(const uint8_t* data, size_t size, size_t* offset)
{
    while (*offset < size) {
        size_t cursor = *offset;
        while (cursor < size && http_ows(data[cursor])) ++cursor;
        if (cursor == size) {
            *offset = cursor;
            return 1;
        }
        if (data[cursor] == ',') {
            *offset = cursor;
            return 2;
        }
        if (data[cursor] != ';') return 0;
        ++cursor;
        while (cursor < size && http_ows(data[cursor])) ++cursor;
        {
            size_t name_start = cursor;
            while (cursor < size && http_tchar(data[cursor])) ++cursor;
            if (cursor == name_start) return 0;
        }
        while (cursor < size && http_ows(data[cursor])) ++cursor;
        if (cursor < size && data[cursor] == '=') {
            ++cursor;
            while (cursor < size && http_ows(data[cursor])) ++cursor;
            if (cursor < size && data[cursor] == '"') {
                if (!http_quoted_valid(data, size, &cursor)) return 0;
            } else {
                size_t value_start = cursor;
                while (cursor < size && http_tchar(data[cursor])) ++cursor;
                if (cursor == value_start) return 0;
            }
            while (cursor < size && http_ows(data[cursor])) ++cursor;
        }
        *offset = cursor;
    }
    return 1;
}

int rin_http_transfer_encoding_final_chunked(const uint8_t* data, size_t size)
{
    size_t offset = 0u;
    RinHttpSlice last = {NULL, 0u};
    int saw_coding = 0;
    if (size != 0u && data == NULL) return RIN_HTTP_INVALID_ARGUMENT;
    while (offset < size) {
        size_t token_start;
        while (offset < size && http_ows(data[offset])) ++offset;
        token_start = offset;
        while (offset < size && http_tchar(data[offset])) ++offset;
        if (offset == token_start) return RIN_HTTP_MALFORMED;
        last.data = data + token_start;
        last.size = offset - token_start;
        saw_coding = 1;
        while (offset < size && http_ows(data[offset])) ++offset;
        if (offset < size && data[offset] == ';') {
            if (!http_parameter_list(data, size, &offset))
                return RIN_HTTP_MALFORMED;
        }
        while (offset < size && http_ows(data[offset])) ++offset;
        if (offset == size) break;
        if (data[offset++] != ',') return RIN_HTTP_MALFORMED;
        if (offset == size) return RIN_HTTP_MALFORMED;
    }
    if (!saw_coding) return RIN_HTTP_MALFORMED;
    return http_slice_literal(last, "chunked") ? 1 : 0;
}

int rin_http_normalize_content_type(const uint8_t* data, size_t size,
                                    char* output, size_t output_capacity,
                                    size_t* output_size)
{
    size_t offset;
    size_t type_start;
    size_t subtype_start;
    size_t type_size;
    size_t subtype_size;
    size_t written;
    if (output_size == NULL || (size != 0u && data == NULL) ||
        (output_capacity != 0u && output == NULL)) {
        if (output_size != NULL) *output_size = 0u;
        return RIN_HTTP_INVALID_ARGUMENT;
    }
    *output_size = 0u;
    offset = http_trim_begin(data, size);
    size = http_trim_end(data, offset, size);
    type_start = offset;
    while (offset < size && http_tchar(data[offset])) ++offset;
    type_size = offset - type_start;
    if (type_size == 0u || offset >= size || data[offset++] != '/')
        return RIN_HTTP_MALFORMED;
    subtype_start = offset;
    while (offset < size && http_tchar(data[offset])) ++offset;
    subtype_size = offset - subtype_start;
    {
        int parameters = http_parameter_list(data, size, &offset);
        if (subtype_size == 0u || parameters != 1 || offset != size)
            return RIN_HTTP_MALFORMED;
    }
    written = type_size + 1u + subtype_size;
    if (written >= output_capacity || output == NULL)
        return RIN_HTTP_BUFFER_TOO_SMALL;
    for (offset = 0u; offset < type_size; ++offset)
        output[offset] = (char)http_lower(data[type_start + offset]);
    output[type_size] = '/';
    for (offset = 0u; offset < subtype_size; ++offset)
        output[type_size + 1u + offset] =
            (char)http_lower(data[subtype_start + offset]);
    output[written] = '\0';
    *output_size = written;
    return RIN_HTTP_OK;
}

int rin_http_parse_authorization(const uint8_t* data, size_t size,
                                 RinHttpAuthorization* authorization)
{
    size_t offset;
    size_t scheme_start;
    size_t credential_start;
    size_t end;
    if (authorization == NULL || (size != 0u && data == NULL))
        return RIN_HTTP_INVALID_ARGUMENT;
    authorization->scheme.data = NULL;
    authorization->scheme.size = 0u;
    authorization->credentials.data = NULL;
    authorization->credentials.size = 0u;
    offset = http_trim_begin(data, size);
    end = http_trim_end(data, offset, size);
    scheme_start = offset;
    while (offset < end && http_tchar(data[offset])) ++offset;
    if (offset == scheme_start) return RIN_HTTP_MALFORMED;
    authorization->scheme.data = data + scheme_start;
    authorization->scheme.size = offset - scheme_start;
    credential_start = offset;
    while (credential_start < end && http_ows(data[credential_start])) ++credential_start;
    if (credential_start == end) return RIN_HTTP_MALFORMED;
    for (offset = credential_start; offset < end; ++offset)
        if (data[offset] == '\r' || data[offset] == '\n' || data[offset] == 0u)
            return RIN_HTTP_MALFORMED;
    authorization->credentials.data = data + credential_start;
    authorization->credentials.size = end - credential_start;
    return RIN_HTTP_OK;
}

static int http_basic_octet_valid(uint8_t value, int username)
{
    return value >= 0x20u && value != 0x7fu &&
           (!username || value != (uint8_t)':');
}

static void http_basic_clear(uint8_t* data, size_t size)
{
    volatile uint8_t* cursor = data;
    while (cursor != NULL && size != 0u) {
        *cursor++ = 0u;
        --size;
    }
}

int rin_http_build_basic_authorization(
    const uint8_t* username, size_t username_size,
    const uint8_t* password, size_t password_size, uint8_t* output,
    size_t output_capacity, size_t* output_size)
{
    uint8_t input[RIN_HTTP_MAX_BASIC_CREDENTIAL_BYTES];
    size_t input_size;
    size_t encoded_size;
    size_t written = 0u;
    size_t index;

    if (output_size != NULL) *output_size = 0u;
    if (output != NULL && output_capacity != 0u) output[0] = 0u;
    memset(input, 0, sizeof(input));
    if (output_size == NULL || output == NULL || output_capacity == 0u ||
        (username == NULL && username_size != 0u) ||
        (password == NULL && password_size != 0u) || username_size == 0u ||
        password_size > RIN_HTTP_MAX_BASIC_CREDENTIAL_BYTES - 1u ||
        username_size > RIN_HTTP_MAX_BASIC_CREDENTIAL_BYTES - 1u -
            password_size) {
        http_basic_clear(input, sizeof(input));
        return RIN_HTTP_INVALID_ARGUMENT;
    }
    for (index = 0u; index < username_size; ++index) {
        if (!http_basic_octet_valid(username[index], 1)) {
            http_basic_clear(input, sizeof(input));
            return RIN_HTTP_MALFORMED;
        }
    }
    for (index = 0u; index < password_size; ++index) {
        if (!http_basic_octet_valid(password[index], 0)) {
            http_basic_clear(input, sizeof(input));
            return RIN_HTTP_MALFORMED;
        }
    }
    input_size = username_size + 1u + password_size;
    memcpy(input, username, username_size);
    input[username_size] = (uint8_t)':';
    memcpy(input + username_size + 1u, password, password_size);
    encoded_size = rin_encoding_base64_encoded_size(input_size, 1);
    if (encoded_size == SIZE_MAX || encoded_size > SIZE_MAX - 7u ||
        output_capacity < 7u + encoded_size) {
        http_basic_clear(input, sizeof(input));
        return RIN_HTTP_BUFFER_TOO_SMALL;
    }
    memcpy(output, "Basic ", 6u);
    if (rin_encoding_base64_encode(
            input, input_size, RIN_ENCODING_BASE64_STANDARD, 1, output + 6u,
            encoded_size, &written) != RIN_ENCODING_OK || written != encoded_size) {
        output[0] = 0u;
        http_basic_clear(input, sizeof(input));
        return RIN_HTTP_MALFORMED;
    }
    output[6u + written] = 0u;
    *output_size = 6u + written;
    http_basic_clear(input, sizeof(input));
    return RIN_HTTP_OK;
}

static void http_response_head_clear(RinHttpResponseHead* output)
{
    size_t index;
    unsigned char* bytes = (unsigned char*)output;
    for (index = 0u; index < sizeof(*output); ++index) bytes[index] = 0u;
}

static int http_response_status_line(const uint8_t* data, size_t size,
                                     uint16_t* status_code)
{
    size_t offset = 0u;
    uint32_t status = 0u;
    unsigned digits;
    if (data == NULL || status_code == NULL || size < 12u ||
        data[0] != 'H' || data[1] != 'T' || data[2] != 'T' ||
        data[3] != 'P' || data[4] != '/') return 0;
    offset = 5u;
    digits = 0u;
    while (offset < size && data[offset] >= '0' && data[offset] <= '9') {
        if (++digits > 3u) return 0;
        ++offset;
    }
    if (digits == 0u || offset >= size || data[offset++] != '.') return 0;
    digits = 0u;
    while (offset < size && data[offset] >= '0' && data[offset] <= '9') {
        if (++digits > 3u) return 0;
        ++offset;
    }
    if (digits == 0u || offset >= size || data[offset++] != ' ') return 0;
    if (offset + 3u > size) return 0;
    for (digits = 0u; digits < 3u; ++digits) {
        if (data[offset] < '0' || data[offset] > '9') return 0;
        status = status * 10u + (uint32_t)(data[offset++] - '0');
    }
    if (status < 100u || status > 599u) return 0;
    while (offset < size) {
        if (data[offset] < 0x20u || data[offset] == 0x7fu) return 0;
        ++offset;
    }
    *status_code = (uint16_t)status;
    return 1;
}

int rin_http_parse_response_head(const uint8_t* data, size_t size,
                                 RinHttpResponseHead* output)
{
    size_t line_start = 0u;
    size_t line_number = 0u;
    if (output == NULL) return RIN_HTTP_INVALID_ARGUMENT;
    http_response_head_clear(output);
    if (data == NULL || size == 0u) return RIN_HTTP_INVALID_ARGUMENT;
    if (size > RIN_HTTP_MAX_RESPONSE_HEADER_BYTES)
        return RIN_HTTP_BUFFER_TOO_SMALL;
    while (line_start < size) {
        size_t line_end = line_start;
        while (line_end + 1u < size &&
               !(data[line_end] == '\r' && data[line_end + 1u] == '\n'))
            ++line_end;
        if (line_end + 1u < size) {
            if (line_end == line_start) goto malformed;
        } else {
            line_end = size;
        }
        if (line_number++ == 0u) {
            if (!http_response_status_line(data, line_end - line_start,
                                           &output->status_code))
                goto malformed;
        } else {
            size_t colon = line_start;
            size_t value_start;
            size_t value_end;
            while (colon < line_end && data[colon] != ':') ++colon;
            if (colon == line_start || colon == line_end ||
                rin_http_field_name_valid(data + line_start,
                                          colon - line_start) != RIN_HTTP_OK)
                goto malformed;
            value_start = colon + 1u;
            value_end = http_trim_end(data, value_start, line_end);
            while (value_start < value_end && http_ows(data[value_start]))
                ++value_start;
            for (size_t index = value_start; index < value_end; ++index) {
                if (data[index] < 0x20u && data[index] != '\t')
                    goto malformed;
                if (data[index] == 0x7fu) goto malformed;
            }
            if (rin_http_field_name_equal(
                    data + line_start, colon - line_start,
                    (const uint8_t*)"content-length", 14u)) {
                if (output->has_content_length ||
                    rin_http_parse_content_length(
                        data + value_start, value_end - value_start,
                        &output->content_length) != RIN_HTTP_OK)
                    goto malformed;
                output->has_content_length = 1u;
            } else if (rin_http_field_name_equal(
                           data + line_start, colon - line_start,
                           (const uint8_t*)"transfer-encoding", 17u)) {
                int transfer_encoding;
                if (output->has_transfer_encoding ||
                    (transfer_encoding =
                         rin_http_transfer_encoding_final_chunked(
                             data + value_start, value_end - value_start)) < 0)
                    goto malformed;
                output->has_transfer_encoding = 1u;
                output->transfer_encoding_chunked =
                    (uint8_t)(transfer_encoding == 1);
            }
        }
        if (line_end == size) break;
        line_start = line_end + 2u;
    }
    if (line_number == 0u) goto malformed;
    return RIN_HTTP_OK;

malformed:
    http_response_head_clear(output);
    return RIN_HTTP_MALFORMED;
}

static int http_fixed_digit(const uint8_t* data, size_t offset,
                            unsigned* value)
{
    if (data[offset] < '0' || data[offset] > '9') return 0;
    *value = (unsigned)(data[offset] - '0');
    return 1;
}

static int http_month(const uint8_t* data)
{
    static const char* const months[] = {"Jan", "Feb", "Mar", "Apr", "May",
        "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"};
    unsigned index;
    for (index = 0u; index < 12u; ++index) {
        if (data[0] == (uint8_t)months[index][0] &&
            data[1] == (uint8_t)months[index][1] &&
            data[2] == (uint8_t)months[index][2]) return (int)index + 1;
    }
    return 0;
}

static int64_t http_days_from_civil(int year, unsigned month, unsigned day)
{
    int adjusted_year = year - (month <= 2u ? 1 : 0);
    int era = (adjusted_year >= 0 ? adjusted_year : adjusted_year - 399) / 400;
    unsigned year_of_era = (unsigned)(adjusted_year - era * 400);
    unsigned month_index = month > 2u ? month - 3u : month + 9u;
    unsigned day_of_year = (153u * month_index + 2u) / 5u + day - 1u;
    unsigned day_of_era = year_of_era * 365u + year_of_era / 4u -
                          year_of_era / 100u + day_of_year;
    return (int64_t)era * 146097ll + (int64_t)day_of_era - 719468ll;
}

int rin_http_parse_imf_fixdate(const uint8_t* data, size_t size,
                               int64_t* unix_seconds)
{
    static const char* const weekdays[] = {"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"};
    unsigned day_tens, day_ones, hour_tens, hour_ones, minute_tens;
    unsigned minute_ones, second_tens, second_ones;
    unsigned year = 0u;
    unsigned index;
    int month;
    unsigned day;
    if (data == NULL || unix_seconds == NULL) return RIN_HTTP_INVALID_ARGUMENT;
    if (size != 29u) return RIN_HTTP_MALFORMED;
    if (data[3] != ',' || data[4] != ' ' || data[7] != ' ' ||
        data[11] != ' ' || data[16] != ' ' || data[19] != ':' ||
        data[22] != ':' || data[25] != ' ' || data[26] != 'G' ||
        data[27] != 'M' || data[28] != 'T') return RIN_HTTP_MALFORMED;
    {
        int weekday_valid = 0;
        for (index = 0u; index < 7u; ++index)
            if (data[0] == (uint8_t)weekdays[index][0] &&
                data[1] == (uint8_t)weekdays[index][1] &&
                data[2] == (uint8_t)weekdays[index][2]) weekday_valid = 1;
        if (!weekday_valid) return RIN_HTTP_MALFORMED;
    }
    if (!http_fixed_digit(data, 5u, &day_tens) ||
        !http_fixed_digit(data, 6u, &day_ones) ||
        !http_fixed_digit(data, 12u, &year) ||
        !http_fixed_digit(data, 13u, &index)) return RIN_HTTP_MALFORMED;
    year = year * 10u + index;
    if (!http_fixed_digit(data, 14u, &index)) return RIN_HTTP_MALFORMED;
    year = year * 10u + index;
    if (!http_fixed_digit(data, 15u, &index)) return RIN_HTTP_MALFORMED;
    year = year * 10u + index;
    month = http_month(data + 8u);
    day = day_tens * 10u + day_ones;
    if (!http_fixed_digit(data, 17u, &hour_tens) ||
        !http_fixed_digit(data, 18u, &hour_ones) ||
        !http_fixed_digit(data, 20u, &minute_tens) ||
        !http_fixed_digit(data, 21u, &minute_ones) ||
        !http_fixed_digit(data, 23u, &second_tens) ||
        !http_fixed_digit(data, 24u, &second_ones) || month == 0 ||
        day == 0u || day > 31u ||
        hour_tens * 10u + hour_ones > 23u ||
        minute_tens * 10u + minute_ones > 59u ||
        second_tens * 10u + second_ones > 59u || year < 1601u)
        return RIN_HTTP_MALFORMED;
    if (day > (month == 2 ? ((year % 4u == 0u &&
                              (year % 100u != 0u || year % 400u == 0u)) ? 29u : 28u) :
               (month == 4 || month == 6 || month == 9 || month == 11 ? 30u : 31u)))
        return RIN_HTTP_MALFORMED;
    *unix_seconds = (http_days_from_civil((int)year, (unsigned)month,
                                          day) * 86400ll) +
                    (int64_t)(hour_tens * 10u + hour_ones) * 3600ll +
                    (int64_t)(minute_tens * 10u + minute_ones) * 60ll +
                    (int64_t)(second_tens * 10u + second_ones);
    return RIN_HTTP_OK;
}

static int http_name_equal_literal(RinHttpSlice slice, const char* name)
{
    size_t index = 0u;
    while (name[index] != '\0') ++index;
    if (slice.size != index) return 0;
    for (index = 0u; index < slice.size; ++index)
        if (http_lower(slice.data[index]) != http_lower((uint8_t)name[index]))
            return 0;
    return 1;
}

int rin_http_cache_directive_find(const uint8_t* data, size_t size,
                                  const char* name, RinHttpSlice* value)
{
    size_t offset = 0u;
    RinHttpSlice found = {NULL, 0u};
    int found_directive = 0;
    if (value != NULL) {
        value->data = NULL;
        value->size = 0u;
    }
    if (data == NULL || name == NULL || value == NULL)
        return RIN_HTTP_INVALID_ARGUMENT;
    for (;;) {
        RinHttpSlice directive;
        size_t start;
        size_t end;
        size_t equals;
        while (offset < size && http_ows(data[offset])) ++offset;
        if (offset == size) return RIN_HTTP_NOT_FOUND;
        start = offset;
        while (offset < size && data[offset] != ',') ++offset;
        end = http_trim_end(data, start, offset);
        if (end == start) return RIN_HTTP_MALFORMED;
        equals = start;
        while (equals < end && data[equals] != '=') ++equals;
        directive.data = data + start;
        directive.size = (equals == end ? end : http_trim_end(data, start, equals)) - start;
        if (rin_http_field_name_valid(directive.data, directive.size) != RIN_HTTP_OK)
            return RIN_HTTP_MALFORMED;
        if (http_name_equal_literal(directive, name)) {
            if (equals != end) {
                size_t value_start = http_trim_begin(data + equals + 1u, end - equals - 1u) + equals + 1u;
                size_t value_end = http_trim_end(data, value_start, end);
                if (value_start == value_end) return RIN_HTTP_MALFORMED;
                if (data[value_start] == '"') {
                    size_t cursor = value_start;
                    if (!http_quoted_valid(data, value_end, &cursor) || cursor != value_end)
                        return RIN_HTTP_MALFORMED;
                } else {
                    size_t cursor;
                    for (cursor = value_start; cursor < value_end; ++cursor)
                        if (!http_tchar(data[cursor])) return RIN_HTTP_MALFORMED;
                }
                found.data = data + value_start;
                found.size = value_end - value_start;
            }
            found_directive = 1;
        }
        if (equals != end) {
            size_t value_start = http_trim_begin(data + equals + 1u, end - equals - 1u) + equals + 1u;
            size_t value_end = http_trim_end(data, value_start, end);
            if (value_start == value_end) return RIN_HTTP_MALFORMED;
            if (data[value_start] == '"') {
                size_t cursor = value_start;
                if (!http_quoted_valid(data, value_end, &cursor) || cursor != value_end)
                    return RIN_HTTP_MALFORMED;
            } else {
                size_t cursor;
                for (cursor = value_start; cursor < value_end; ++cursor)
                    if (!http_tchar(data[cursor])) return RIN_HTTP_MALFORMED;
            }
        }
        if (offset == size) {
            if (found_directive != 0) *value = found;
            return found_directive != 0 ? RIN_HTTP_OK : RIN_HTTP_NOT_FOUND;
        }
        ++offset;
        if (offset == size) return RIN_HTTP_MALFORMED;
    }
}

int rin_http_redirect_target_valid(const uint8_t* data, size_t size)
{
    RinUri uri;
    if (data == NULL || size == 0u || size > RIN_URI_MAX_BYTES)
        return RIN_HTTP_INVALID_ARGUMENT;
    if (rin_uri_parse((const char*)data, size, &uri) != RIN_URI_OK ||
        uri.is_absolute == 0u || uri.has_authority == 0u ||
        uri.host.size == 0u || uri.has_userinfo != 0u ||
        (!rin_uri_scheme_is(&uri, "http") && !rin_uri_scheme_is(&uri, "https")))
        return RIN_HTTP_MALFORMED;
    return RIN_HTTP_OK;
}
