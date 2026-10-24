/*
 * codesign: option adapter over the real Security.framework signer.
 *
 * Provenance (2026-10-24), per the missing-API rule:
 *   vendored: OSX/libsecurity_codesigning/lib/{SecCodeSigner,signer}.cpp is the
 *             real signer. signer.cpp generates entitlement DER when the
 *             SecCodeSignerCreate operation flag kSecCSSignGenerateEntitlementDER
 *             (1 << 9) is set; the slot is cdEntitlementDERSlot (7).
 *             There is no genuine codesign CLI here: SecurityTool/sharedTool/
 *             codesign.c is TARGET_OS_IPHONE && !TARGET_OS_SIMULATOR verify-only;
 *             codesign_wrapper shells out to /usr/bin/codesign; cctools'
 *             codesign_allocate only allocates Mach-O signature space.
 *   newer upstream: Apple Security signer.cpp carries the same DER signer and
 *             operation-bit contract. The Apple CLI option front end is not in
 *             this source tree.
 *   sibling: vibedarling/darling/src/tools/codesign.c is a fake-success stub
 *             ("DID NOT ACTUALLY VERIFY..."); it is rejected and not built here.
 *
 * This file is therefore only the option/API adapter. Signatures, CodeDirectory,
 * CMS/adhoc handling, entitlements and DER are produced by Security.framework.
 * The entitlement blob wrapper below is the existing builder from the historical
 * codesign_wrapper.c (CSMAGIC_EMBEDDED_ENTITLEMENTS); no serializer is added.
 *
 * Flag domains kept distinct:
 *   - SecCodeSignerCreate flags: operation flags; DER bit belongs here.
 *   - kSecCodeSignerFlags dictionary value: CodeDirectory signature flags; not
 *     used for --generate-entitlement-der.
 *   - SecCodeSignerAddSignature[WithErrors] flags: only kSecCSReportProgress;
 *     no DER or operation bits are passed there.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <Security/SecCodeSigner.h>
#include <Security/SecStaticCode.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum { CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xfade7171 };

typedef struct {
    uint32_t type;
    uint32_t offset;
} cs_blob_index;

/* Existing wrapper builder; only wraps the .xcent plist bytes, does not sign. */
static CFDataRef build_entitlements_blob(const uint8_t *data, size_t length)
{
    cs_blob_index csbi = {
        htonl(CSMAGIC_EMBEDDED_ENTITLEMENTS),
        htonl((uint32_t)(length + sizeof(csbi)))
    };
    CFMutableDataRef blob =
        CFDataCreateMutable(kCFAllocatorDefault, (CFIndex)(sizeof(csbi) + length));
    if (blob == NULL)
        return NULL;
    CFDataAppendBytes(blob, (const UInt8 *)&csbi, (CFIndex)sizeof(csbi));
    if (data != NULL && length != 0)
        CFDataAppendBytes(blob, data, (CFIndex)length);
    return blob;
}

static CFDataRef read_file(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        fprintf(stderr, "codesign: cannot open %s: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fprintf(stderr, "codesign: cannot seek %s\n", path);
        fclose(f);
        return NULL;
    }
    long size = ftell(f);
    if (size < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fprintf(stderr, "codesign: cannot size %s\n", path);
        fclose(f);
        return NULL;
    }
    CFMutableDataRef data =
        CFDataCreateMutable(kCFAllocatorDefault, (CFIndex)size);
    if (data == NULL) {
        fclose(f);
        return NULL;
    }
    uint8_t buf[65536];
    long remaining = size;
    while (remaining > 0) {
        size_t want = (size_t)(remaining < (long)sizeof(buf) ? remaining
                                                             : (long)sizeof(buf));
        size_t got = fread(buf, 1, want, f);
        if (got == 0) {
            fprintf(stderr, "codesign: short read %s\n", path);
            CFRelease(data);
            fclose(f);
            return NULL;
        }
        CFDataAppendBytes(data, buf, (CFIndex)got);
        remaining -= (long)got;
    }
    fclose(f);
    return data;
}

static int fail_status(const char *what, OSStatus status)
{
    fprintf(stderr, "codesign: %s failed: OSStatus %d\n", what, (int)status);
    return 1;
}

static void usage(void)
{
    fprintf(stderr,
        "usage: codesign --force --sign - [--entitlements PATH] "
        "[--timestamp=none] [--generate-entitlement-der] PATH\n");
}

int main(int argc, char *argv[])
{
    const char *target = NULL;
    const char *entitlements_path = NULL;
    int force = 0;
    int ad_hoc = 0;
    int timestamp_none = 0;
    int generate_der = 0;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "--force") == 0) {
            force = 1;
        } else if (strcmp(arg, "--sign") == 0) {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            const char *identity = argv[++i];
            if (strcmp(identity, "-") != 0) {
                fprintf(stderr,
                    "codesign: only ad-hoc identity '-' is supported here\n");
                return 2;
            }
            ad_hoc = 1;
        } else if (strcmp(arg, "--entitlements") == 0) {
            if (i + 1 >= argc) {
                usage();
                return 2;
            }
            entitlements_path = argv[++i];
        } else if (strcmp(arg, "--timestamp=none") == 0) {
            timestamp_none = 1;
        } else if (strcmp(arg, "--generate-entitlement-der") == 0) {
            generate_der = 1;
        } else if (arg[0] == '-') {
            fprintf(stderr, "codesign: unsupported option %s\n", arg);
            return 2;
        } else if (target == NULL) {
            target = arg;
        } else {
            fprintf(stderr, "codesign: multiple targets\n");
            return 2;
        }
    }

    if (!force || !ad_hoc || target == NULL) {
        usage();
        return 2;
    }
    (void)timestamp_none; /* enforced below: no timestamp is requested */

    CFMutableDictionaryRef parameters = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 0,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    if (parameters == NULL)
        return 1;

    /* Mandatory ad-hoc identity is kCFNull, not an omitted key. */
    CFDictionarySetValue(parameters, kSecCodeSignerIdentity, kCFNull);

    if (entitlements_path != NULL) {
        CFDataRef plist = read_file(entitlements_path);
        if (plist == NULL) {
            CFRelease(parameters);
            return 1;
        }
        CFDataRef blob = build_entitlements_blob(
            CFDataGetBytePtr(plist), (size_t)CFDataGetLength(plist));
        CFRelease(plist);
        if (blob == NULL) {
            CFRelease(parameters);
            return 1;
        }
        CFDictionarySetValue(parameters, kSecCodeSignerEntitlements, blob);
        CFRelease(blob);
    }

    if (timestamp_none)
        CFDictionarySetValue(parameters, kSecCodeSignerRequireTimestamp,
                             kCFBooleanFalse);

    /*
     * Operation flags go to SecCodeSignerCreate. kSecCSSignGenerateEntitlementDER
     * is allowed by SecCodeSignerCreate's checkFlags; it is not a
     * kSecCodeSignerFlags CodeDirectory flag and not an AddSignature flag.
     * --force requests replacement; the signer's default is to (re)sign, so no
     * kSecCSSignPreserveSignature bit is added.
     */
    SecCSFlags operation_flags = kSecCSDefaultFlags;
    if (generate_der)
        operation_flags |= kSecCSSignGenerateEntitlementDER;

    SecCodeSignerRef signer = NULL;
    OSStatus status = SecCodeSignerCreate(parameters, operation_flags, &signer);
    CFRelease(parameters);
    if (status != 0)
        return fail_status("SecCodeSignerCreate", status);

    CFURLRef url = CFURLCreateFromFileSystemRepresentation(
        kCFAllocatorDefault, (const UInt8 *)target, (CFIndex)strlen(target), false);
    if (url == NULL) {
        CFRelease(signer);
        return 1;
    }
    SecStaticCodeRef code = NULL;
    status = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, &code);
    CFRelease(url);
    if (status != 0) {
        CFRelease(signer);
        return fail_status("SecStaticCodeCreateWithPath", status);
    }

    /*
     * AddSignature flags are a third domain: only kSecCSReportProgress is
     * accepted. Passing the DER operation bit here would be wrong.
     */
    CFErrorRef error = NULL;
    status = SecCodeSignerAddSignatureWithErrors(
        signer, code, kSecCSDefaultFlags, &error);
    CFRelease(code);
    CFRelease(signer);
    if (status != 0) {
        if (error != NULL) {
            CFStringRef desc = CFErrorCopyDescription(error);
            if (desc != NULL) {
                char buf[1024];
                if (CFStringGetCString(desc, buf, sizeof(buf),
                                       kCFStringEncodingUTF8))
                    fprintf(stderr, "codesign: sign error: %s\n", buf);
                CFRelease(desc);
            }
            CFRelease(error);
        }
        return fail_status("SecCodeSignerAddSignatureWithErrors", status);
    }
    return 0;
}
