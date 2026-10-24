/*
 * V1 DER entitlements serialization (separate from the legacy SET codec).
 *
 * Provenance: the vendored V0 codec is der_plist.c/der_dictionary.c (legacy SET);
 * Apple's newer CoreEntitlements implementation is not in this tree (XNU ships only
 * headers); the native macOS 26.6.2 /usr/bin/derq outputs sealed in
 * evidence/derq-native-contract-20261024b.tar.zst are the V1 wire oracle.
 *
 * Native V1 shape: APPLICATION 16 constructed { INTEGER 1, [16] dictionary }.
 * A dictionary is [16] constructed containing SEQUENCE key/value entries, ordered by
 * UTF-8 key bytes. Arrays are SEQUENCE. Legacy APIs are unchanged.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <corecrypto/ccder.h>
#include <stdlib.h>
#include <string.h>

#include "utilities/der_plist.h"
#include "utilities/der_plist_internal.h"
#include "utilities/der_plist_v1.h"
#include "utilities/SecCFError.h"
#include "utilities/SecCFRelease.h"

enum {
    CCDER_APPLICATION_16 = CCDER_APPLICATION | CCDER_CONSTRUCTED | 16,
    CCDER_CONTEXT_16 = CCDER_CONTEXT_SPECIFIC | CCDER_CONSTRUCTED | 16,
};

static size_t der_sizeof_v1_value(CFTypeRef value, CFErrorRef *error);
static uint8_t *der_encode_v1_value(CFTypeRef value, CFErrorRef *error,
                                    const uint8_t *der, uint8_t *der_end);

static bool v1_check_string(CFStringRef string, bool is_key, CFErrorRef *error)
{
    if (is_key && CFStringGetLength(string) == 0) {
        SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                            CFSTR("empty V1 entitlement key"), NULL, error);
        return false;
    }

    CFIndex length = CFStringGetLength(string);
    CFIndex maximum = CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8);
    if (maximum < 0) {
        SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                            CFSTR("V1 string size overflow"), NULL, error);
        return false;
    }

    uint8_t *buffer = malloc(maximum > 0 ? (size_t)maximum : 1);
    if (buffer == NULL) {
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 string allocation failed"), NULL, error);
        return false;
    }

    CFIndex used = 0;
    CFIndex converted = CFStringGetBytes(string, CFRangeMake(0, length),
                                         kCFStringEncodingUTF8, 0, false,
                                         buffer, maximum, &used);
    if (converted != length) {
        free(buffer);
        SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                            CFSTR("V1 string extraction failed"), NULL, error);
        return false;
    }

    for (CFIndex i = 0; i < used; ++i) {
        if (buffer[i] == 0) {
            free(buffer);
            SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                                CFSTR("NUL in V1 entitlement string"), NULL, error);
            return false;
        }
    }

    free(buffer);
    return true;
}

static bool v1_number_to_int64(CFNumberRef number, long long *value)
{
    /* Keep integer numbers on their actual CF integer representation. In
     * particular the XML parser stores values above INT64_MAX as a private
     * 128-bit CFNumber; CFNumberGetValue(SInt64) preserves the low 64 bits,
     * which is the native wrap (UINT64_MAX -> -1, 2^63 -> INT64_MIN). */
    if (!CFNumberIsFloatType(number)) {
        return CFNumberGetValue(number, kCFNumberSInt64Type, value) != false;
    }

    /* A real is a double CFNumber. Truncate toward zero, matching the native
     * 1.5 -> 1 result, but reject NaN, infinity and values outside the
     * representable signed 64-bit range before performing the cast. */
    double double_value = 0;
    if (!CFNumberGetValue(number, kCFNumberDoubleType, &double_value)) {
        return false;
    }
    if (double_value != double_value ||
        double_value < -9223372036854775808.0 ||
        double_value >= 9223372036854775808.0) {
        return false;
    }
    *value = (long long)double_value;
    return true;
}

static size_t der_sizeof_v1_number(CFNumberRef number, CFErrorRef *error)
{
    long long value = 0;
    if (!v1_number_to_int64(number, &value)) {
        SecCFDERCreateError(kSecDERErrorUnsupportedNumberType,
                            CFSTR("unsupported V1 number"), NULL, error);
        return 0;
    }
    CFNumberRef converted = CFNumberCreate(NULL, kCFNumberLongLongType, &value);
    if (converted == NULL) {
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 number allocation failed"), NULL, error);
        return 0;
    }
    size_t size = der_sizeof_number(converted, error);
    CFRelease(converted);
    return size;
}

static uint8_t *der_encode_v1_number(CFNumberRef number, CFErrorRef *error,
                                     const uint8_t *der, uint8_t *der_end)
{
    long long value = 0;
    if (!v1_number_to_int64(number, &value)) {
        SecCFDERCreateError(kSecDERErrorUnsupportedNumberType,
                            CFSTR("unsupported V1 number"), NULL, error);
        return NULL;
    }
    CFNumberRef converted = CFNumberCreate(NULL, kCFNumberLongLongType, &value);
    if (converted == NULL) {
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 number allocation failed"), NULL, error);
        return NULL;
    }
    uint8_t *result = der_encode_number(converted, error, der, der_end);
    CFRelease(converted);
    return result;
}

static size_t der_sizeof_v1_array(CFArrayRef array, CFErrorRef *error)
{
    size_t total = 0;
    for (CFIndex i = 0; i < CFArrayGetCount(array); ++i) {
        size_t size = der_sizeof_v1_value(CFArrayGetValueAtIndex(array, i), error);
        if (size == 0) {
            return 0;
        }
        total += size;
    }
    return ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE, total);
}

static uint8_t *der_encode_v1_array(CFArrayRef array, CFErrorRef *error,
                                    const uint8_t *der, uint8_t *der_end)
{
    uint8_t *const original_end = der_end;
    uint8_t *body_end = der_end;
    for (CFIndex i = CFArrayGetCount(array); i > 0;) {
        --i;
        body_end = der_encode_v1_value(CFArrayGetValueAtIndex(array, i),
                                       error, der, body_end);
        if (body_end == NULL) {
            return NULL;
        }
    }
    return SecCCDEREncodeHandleResult(
        ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE,
                                    original_end, der, body_end),
        error);
}

static size_t der_sizeof_v1_key_value(CFStringRef key, CFTypeRef value,
                                      CFErrorRef *error)
{
    size_t key_size = der_sizeof_string(key, error);
    if (key_size == 0) {
        return 0;
    }
    size_t value_size = der_sizeof_v1_value(value, error);
    if (value_size == 0) {
        return 0;
    }
    return ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE, key_size + value_size);
}

struct v1_size_context {
    bool success;
    size_t size;
    CFErrorRef *error;
};

static void v1_add_key_value_size(const void *key, const void *value,
                                  void *context)
{
    struct v1_size_context *ctx = context;
    if (!ctx->success) {
        return;
    }
    size_t size = der_sizeof_v1_key_value((CFStringRef)key, (CFTypeRef)value,
                                          ctx->error);
    if (size == 0) {
        ctx->success = false;
        return;
    }
    ctx->size += size;
}

static size_t der_sizeof_v1_dictionary(CFDictionaryRef dictionary,
                                       CFErrorRef *error)
{
    struct v1_size_context ctx = { true, 0, error };
    CFDictionaryApplyFunction(dictionary, v1_add_key_value_size, &ctx);
    if (!ctx.success) {
        return 0;
    }
    return ccder_sizeof(CCDER_CONTEXT_16, ctx.size);
}

static size_t der_sizeof_v1_value(CFTypeRef value, CFErrorRef *error)
{
    if (value == NULL) {
        SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                            CFSTR("null V1 entitlement value"), NULL, error);
        return 0;
    }

    CFTypeID type = CFGetTypeID(value);
    if (type == CFBooleanGetTypeID()) {
        return der_sizeof_boolean((CFBooleanRef)value, error);
    }
    if (type == CFNumberGetTypeID()) {
        return der_sizeof_v1_number((CFNumberRef)value, error);
    }
    if (type == CFStringGetTypeID()) {
        if (!v1_check_string((CFStringRef)value, false, error)) {
            return 0;
        }
        return der_sizeof_string((CFStringRef)value, error);
    }
    if (type == CFArrayGetTypeID()) {
        return der_sizeof_v1_array((CFArrayRef)value, error);
    }
    if (type == CFDictionaryGetTypeID()) {
        return der_sizeof_v1_dictionary((CFDictionaryRef)value, error);
    }

    SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                        CFSTR("unsupported V1 entitlement type"), NULL, error);
    return 0;
}

static uint8_t *der_encode_v1_entry(CFStringRef key, CFTypeRef value,
                                    CFErrorRef *error,
                                    const uint8_t *der, uint8_t *der_end)
{
    uint8_t *const original_end = der_end;
    uint8_t *body_end = der_encode_v1_value(value, error, der, der_end);
    if (body_end == NULL) {
        return NULL;
    }
    body_end = der_encode_string(key, error, der, body_end);
    if (body_end == NULL) {
        return NULL;
    }
    return SecCCDEREncodeHandleResult(
        ccder_encode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE,
                                    original_end, der, body_end),
        error);
}

static CFComparisonResult v1_compare_utf8_keys(const void *a, const void *b,
                                               void *context)
{
    (void)context;
    CFStringRef key_a = (CFStringRef)a;
    CFStringRef key_b = (CFStringRef)b;

    CFIndex length_a = CFStringGetLength(key_a);
    CFIndex length_b = CFStringGetLength(key_b);
    CFIndex maximum_a = CFStringGetMaximumSizeForEncoding(length_a, kCFStringEncodingUTF8);
    CFIndex maximum_b = CFStringGetMaximumSizeForEncoding(length_b, kCFStringEncodingUTF8);

    uint8_t *bytes_a = malloc(maximum_a > 0 ? (size_t)maximum_a : 1);
    uint8_t *bytes_b = malloc(maximum_b > 0 ? (size_t)maximum_b : 1);
    if (bytes_a == NULL || bytes_b == NULL) {
        free(bytes_a);
        free(bytes_b);
        return kCFCompareEqualTo;
    }

    CFIndex used_a = 0;
    CFIndex used_b = 0;
    CFStringGetBytes(key_a, CFRangeMake(0, length_a), kCFStringEncodingUTF8, 0,
                     false, bytes_a, maximum_a, &used_a);
    CFStringGetBytes(key_b, CFRangeMake(0, length_b), kCFStringEncodingUTF8, 0,
                     false, bytes_b, maximum_b, &used_b);

    CFIndex minimum = used_a < used_b ? used_a : used_b;
    int compared = memcmp(bytes_a, bytes_b, (size_t)minimum);
    free(bytes_a);
    free(bytes_b);

    if (compared < 0) {
        return kCFCompareLessThan;
    }
    if (compared > 0) {
        return kCFCompareGreaterThan;
    }
    if (used_a < used_b) {
        return kCFCompareLessThan;
    }
    if (used_a > used_b) {
        return kCFCompareGreaterThan;
    }
    return kCFCompareEqualTo;
}

static bool v1_check_canonical_duplicates(CFArrayRef keys, CFErrorRef *error)
{
    CFIndex count = CFArrayGetCount(keys);
    for (CFIndex i = 0; i < count; ++i) {
        for (CFIndex j = i + 1; j < count; ++j) {
            CFStringRef a = CFArrayGetValueAtIndex(keys, i);
            CFStringRef b = CFArrayGetValueAtIndex(keys, j);
            if (CFStringCompare(a, b, kCFCompareNonliteral) == kCFCompareEqualTo) {
                SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                                    CFSTR("canonically equivalent V1 entitlement keys"),
                                    NULL, error);
                return false;
            }
        }
    }
    return true;
}

static uint8_t *der_encode_v1_dictionary(CFDictionaryRef dictionary,
                                         CFErrorRef *error,
                                         const uint8_t *der, uint8_t *der_end)
{
    uint8_t *const original_end = der_end;
    CFIndex count = CFDictionaryGetCount(dictionary);
    if (count < 0) {
        SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                            CFSTR("invalid V1 dictionary"), NULL, error);
        return NULL;
    }

    if (count == 0) {
        return SecCCDEREncodeHandleResult(
            ccder_encode_constructed_tl(CCDER_CONTEXT_16,
                                        original_end, der, der_end),
            error);
    }

    const void **keys = malloc(sizeof(void *) * (size_t)count);
    if (keys == NULL) {
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 key allocation failed"), NULL, error);
        return NULL;
    }

    CFDictionaryGetKeysAndValues(dictionary, keys, NULL);

    for (CFIndex i = 0; i < count; ++i) {
        CFStringRef key = (CFStringRef)keys[i];
        if (CFGetTypeID(key) != CFStringGetTypeID()) {
            SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                                CFSTR("V1 entitlement key is not a string"),
                                NULL, error);
            free(keys);
            return NULL;
        }
        if (!v1_check_string(key, true, error)) {
            free(keys);
            return NULL;
        }
    }

    CFMutableArrayRef sorted_keys = CFArrayCreateMutable(NULL, count, &kCFTypeArrayCallBacks);
    if (sorted_keys == NULL) {
        free(keys);
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 key array allocation failed"), NULL, error);
        return NULL;
    }

    for (CFIndex i = 0; i < count; ++i) {
        CFArrayAppendValue(sorted_keys, keys[i]);
    }

    if (!v1_check_canonical_duplicates(sorted_keys, error)) {
        CFRelease(sorted_keys);
        free(keys);
        return NULL;
    }

    CFArraySortValues(sorted_keys, CFRangeMake(0, count), v1_compare_utf8_keys, NULL);

    /* The destination was sized by der_sizeof_v1_dictionary. Encode the sorted
     * entries directly into it in reverse order, so no per-entry CFData
     * allocation or copy is needed. */
    uint8_t *body_end = der_end;
    for (CFIndex i = count; i > 0;) {
        --i;
        CFStringRef key = CFArrayGetValueAtIndex(sorted_keys, i);
        CFTypeRef value = CFDictionaryGetValue(dictionary, key);
        size_t entry_size = der_sizeof_v1_key_value(key, value, error);
        if (entry_size == 0 || body_end < der ||
            (size_t)(body_end - der) < entry_size) {
            if (entry_size != 0) {
                SecCFDERCreateError(kSecDERErrorAllocationFailure,
                                    CFSTR("V1 dictionary size mismatch"), NULL, error);
            }
            CFRelease(sorted_keys);
            free(keys);
            return NULL;
        }
        uint8_t *entry_begin = body_end - entry_size;
        if (der_encode_v1_entry(key, value, error, entry_begin, body_end) != entry_begin) {
            CFRelease(sorted_keys);
            free(keys);
            return NULL;
        }
        body_end = entry_begin;
    }

    if (body_end != der) {
        CFRelease(sorted_keys);
        free(keys);
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 dictionary size mismatch"), NULL, error);
        return NULL;
    }

    CFRelease(sorted_keys);
    free(keys);

    return SecCCDEREncodeHandleResult(
        ccder_encode_constructed_tl(CCDER_CONTEXT_16,
                                    original_end, der, body_end),
        error);
}

static uint8_t *der_encode_v1_value(CFTypeRef value, CFErrorRef *error,
                                    const uint8_t *der, uint8_t *der_end)
{
    if (value == NULL) {
        SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                            CFSTR("null V1 entitlement value"), NULL, error);
        return NULL;
    }

    CFTypeID type = CFGetTypeID(value);
    if (type == CFBooleanGetTypeID()) {
        return der_encode_boolean((CFBooleanRef)value, error, der, der_end);
    }
    if (type == CFNumberGetTypeID()) {
        return der_encode_v1_number((CFNumberRef)value, error, der, der_end);
    }
    if (type == CFStringGetTypeID()) {
        if (!v1_check_string((CFStringRef)value, false, error)) {
            return NULL;
        }
        return der_encode_string((CFStringRef)value, error, der, der_end);
    }
    if (type == CFArrayGetTypeID()) {
        return der_encode_v1_array((CFArrayRef)value, error, der, der_end);
    }
    if (type == CFDictionaryGetTypeID()) {
        return der_encode_v1_dictionary((CFDictionaryRef)value, error, der, der_end);
    }

    SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                        CFSTR("unsupported V1 entitlement type"), NULL, error);
    return NULL;
}

CFDataRef CFPropertyListCreateDEREntitlementsV1Inner(CFAllocatorRef allocator,
                                                     CFPropertyListRef plist,
                                                     CFErrorRef *error)
{
    if (plist == NULL || CFGetTypeID(plist) != CFDictionaryGetTypeID()) {
        SecCFDERCreateError(kSecDERErrorUnsupportedCFObject,
                            CFSTR("V1 entitlements root must be a dictionary"),
                            NULL, error);
        return NULL;
    }

    size_t size = der_sizeof_v1_dictionary((CFDictionaryRef)plist, error);
    if (size == 0) {
        return NULL;
    }

    CFMutableDataRef result = CFDataCreateMutable(allocator, (CFIndex)size);
    if (result == NULL) {
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 entitlements allocation failed"),
                            NULL, error);
        return NULL;
    }
    CFDataSetLength(result, (CFIndex)size);

    uint8_t *begin = CFDataGetMutableBytePtr(result);
    uint8_t *end = begin + size;
    if (der_encode_v1_dictionary((CFDictionaryRef)plist, error, begin, end) != begin) {
        CFRelease(result);
        return NULL;
    }

    return result;
}

CFDataRef CFPropertyListCreateDEREntitlementsV1(CFAllocatorRef allocator,
                                                CFPropertyListRef plist,
                                                CFErrorRef *error)
{
    CFDataRef inner = CFPropertyListCreateDEREntitlementsV1Inner(allocator, plist, error);
    if (inner == NULL) {
        return NULL;
    }

    CFIndex inner_length = CFDataGetLength(inner);
    size_t version_size = ccder_sizeof(CCDER_INTEGER, 1);
    size_t outer_size = ccder_sizeof(CCDER_APPLICATION_16,
                                     version_size + (size_t)inner_length);

    CFMutableDataRef result = CFDataCreateMutable(allocator, (CFIndex)outer_size);
    if (result == NULL) {
        CFRelease(inner);
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 outer allocation failed"), NULL, error);
        return NULL;
    }
    CFDataSetLength(result, (CFIndex)outer_size);

    uint8_t *begin = CFDataGetMutableBytePtr(result);
    uint8_t *end = begin + outer_size;
    uint8_t *body_end = end - inner_length;
    memcpy(body_end, CFDataGetBytePtr(inner), (size_t)inner_length);
    CFRelease(inner);

    long long one_value = 1;
    CFNumberRef one = CFNumberCreate(NULL, kCFNumberLongLongType, &one_value);
    if (one == NULL) {
        CFRelease(result);
        SecCFDERCreateError(kSecDERErrorAllocationFailure,
                            CFSTR("V1 version allocation failed"), NULL, error);
        return NULL;
    }
    body_end = der_encode_number(one, error, begin, body_end);
    CFRelease(one);
    if (body_end == NULL) {
        CFRelease(result);
        return NULL;
    }

    if (ccder_encode_constructed_tl(CCDER_APPLICATION_16, end, begin, body_end) != begin) {
        CFRelease(result);
        SecCFDERCreateError(kSecDERErrorUnknownEncoding,
                            CFSTR("V1 outer encoding failed"), NULL, error);
        return NULL;
    }

    return result;
}
