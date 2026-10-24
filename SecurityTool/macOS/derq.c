/*
 * derq: V1 DER entitlements conversion for the build's
 * `query -f xml -i IN -o OUT --raw` path.
 *
 * Supported path only: XML input, zero query statements. --raw emits the full
 * APPLICATION 16 { INTEGER 1, [16] dictionary } wrapper; without --raw emits the
 * inner [16] dictionary, matching the native macOS derq option evidence.
 * Unsupported commands/options fail explicitly; malformed input never falls back
 * to an empty dictionary.
 */
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "utilities/der_plist_v1.h"
#include "utilities/SecCFError.h"

#define DERQ_INVALID_ARGUMENTS 65
#define DERQ_OPERATIONAL_FAILURE 1

static void usage(FILE *stream)
{
    fprintf(stream, "usage: derq query -f xml -i INPUT -o OUTPUT [--raw]\n");
}

static bool read_all(FILE *file, uint8_t **data_out, size_t *length_out)
{
    size_t capacity = 4096;
    size_t used = 0;
    uint8_t *buffer = malloc(capacity);
    if (buffer == NULL) {
        return false;
    }

    for (;;) {
        if (used == capacity) {
            if (capacity > (SIZE_MAX / 2)) {
                free(buffer);
                return false;
            }
            capacity *= 2;
            uint8_t *grown = realloc(buffer, capacity);
            if (grown == NULL) {
                free(buffer);
                return false;
            }
            buffer = grown;
        }

        size_t read_count = fread(buffer + used, 1, capacity - used, file);
        used += read_count;
        if (read_count == 0) {
            if (ferror(file)) {
                free(buffer);
                return false;
            }
            break;
        }
    }

    *data_out = buffer;
    *length_out = used;
    return true;
}

static bool write_all(FILE *file, const uint8_t *data, size_t length)
{
    while (length > 0) {
        size_t written = fwrite(data, 1, length, file);
        if (written == 0) {
            return false;
        }
        data += written;
        length -= written;
    }
    return true;
}

static bool contains_bytes(const uint8_t *data, size_t length, const char *needle)
{
    size_t needle_length = strlen(needle);
    if (needle_length == 0 || needle_length > length) {
        return false;
    }
    for (size_t i = 0; i + needle_length <= length; ++i) {
        if (memcmp(data + i, needle, needle_length) == 0) {
            return true;
        }
    }
    return false;
}

static void print_error(CFErrorRef error, const char *fallback)
{
    if (error != NULL) {
        CFStringRef description = CFErrorCopyDescription(error);
        if (description != NULL) {
            char buffer[1024];
            if (CFStringGetCString(description, buffer, sizeof(buffer),
                                   kCFStringEncodingUTF8)) {
                fprintf(stderr, "derq: %s\n", buffer);
            } else {
                fprintf(stderr, "derq: %s\n", fallback);
            }
            CFRelease(description);
            return;
        }
    }
    fprintf(stderr, "derq: %s\n", fallback);
}

int main(int argc, char **argv)
{
    const char *format = NULL;
    const char *input_path = "-";
    const char *output_path = "-";
    bool raw = false;

    int index = 1;
    if (index >= argc || strcmp(argv[index], "query") != 0) {
        usage(stderr);
        return DERQ_INVALID_ARGUMENTS;
    }
    ++index;

    while (index < argc) {
        const char *argument = argv[index];
        if (strcmp(argument, "-f") == 0) {
            if (index + 1 >= argc) {
                usage(stderr);
                return DERQ_INVALID_ARGUMENTS;
            }
            format = argv[++index];
            ++index;
        } else if (strcmp(argument, "-i") == 0) {
            if (index + 1 >= argc) {
                usage(stderr);
                return DERQ_INVALID_ARGUMENTS;
            }
            input_path = argv[++index];
            ++index;
        } else if (strcmp(argument, "-o") == 0) {
            if (index + 1 >= argc) {
                usage(stderr);
                return DERQ_INVALID_ARGUMENTS;
            }
            output_path = argv[++index];
            ++index;
        } else if (strcmp(argument, "--raw") == 0) {
            raw = true;
            ++index;
        } else {
            fprintf(stderr, "derq: unsupported option or query statement: %s\n", argument);
            return DERQ_INVALID_ARGUMENTS;
        }
    }

    if (format == NULL || strcmp(format, "xml") != 0) {
        fprintf(stderr, "derq: only -f xml input is supported\n");
        return DERQ_INVALID_ARGUMENTS;
    }

    FILE *input = strcmp(input_path, "-") == 0 ? stdin : fopen(input_path, "rb");
    if (input == NULL) {
        perror(input_path);
        return DERQ_OPERATIONAL_FAILURE;
    }

    uint8_t *input_bytes = NULL;
    size_t input_length = 0;
    if (!read_all(input, &input_bytes, &input_length)) {
        if (input != stdin) {
            fclose(input);
        }
        fprintf(stderr, "derq: failed to read input\n");
        return DERQ_OPERATIONAL_FAILURE;
    }
    if (input != stdin) {
        fclose(input);
    }

    if (!contains_bytes(input_bytes, input_length, "<plist") ||
        !contains_bytes(input_bytes, input_length, "</plist>")) {
        free(input_bytes);
        fprintf(stderr, "derq: input is not an XML property list\n");
        return DERQ_OPERATIONAL_FAILURE;
    }

    CFDataRef input_data = CFDataCreate(NULL, input_bytes, (CFIndex)input_length);
    free(input_bytes);
    if (input_data == NULL) {
        fprintf(stderr, "derq: input allocation failed\n");
        return DERQ_OPERATIONAL_FAILURE;
    }

    CFErrorRef error = NULL;
    CFPropertyListRef plist = CFPropertyListCreateWithData(NULL, input_data,
                                                           kCFPropertyListImmutable,
                                                           NULL, &error);
    CFRelease(input_data);
    if (plist == NULL) {
        print_error(error, "input is not a property list");
        if (error != NULL) {
            CFRelease(error);
        }
        return DERQ_OPERATIONAL_FAILURE;
    }

    CFDataRef encoded = raw
        ? CFPropertyListCreateDEREntitlementsV1(NULL, plist, &error)
        : CFPropertyListCreateDEREntitlementsV1Inner(NULL, plist, &error);
    CFRelease(plist);
    if (encoded == NULL) {
        print_error(error, "failed to serialize V1 entitlements");
        if (error != NULL) {
            CFRelease(error);
        }
        return DERQ_OPERATIONAL_FAILURE;
    }

    FILE *output = strcmp(output_path, "-") == 0 ? stdout : fopen(output_path, "wb");
    if (output == NULL) {
        CFRelease(encoded);
        perror(output_path);
        return DERQ_OPERATIONAL_FAILURE;
    }

    bool written = write_all(output,
                             CFDataGetBytePtr(encoded),
                             (size_t)CFDataGetLength(encoded));
    CFRelease(encoded);
    if (output == stdout) {
        if (fflush(output) != 0) {
            written = false;
        }
    } else if (fclose(output) != 0) {
        written = false;
    }
    if (!written) {
        fprintf(stderr, "derq: failed to write output\n");
        return DERQ_OPERATIONAL_FAILURE;
    }

    return 0;
}
