# darling-security

## Upstream URL

https://github.com/apple-oss-distributions/Security/tree/Security-59754.140.13

## Updating Source

When updating the source code, make sure to refer to the [`Updating Sources`](https://docs.darlinghq.org/contributing/updating-sources/index.html#updating-sources) section from the Darling Docs website. Additional details (if any) can be found in [`darling/notes/UPDATE_SOURCE.md`](darling/notes/UPDATE_SOURCE.md).

## Apple trust anchors

`SecTrustGetAppleAnchors(void)` returns a borrowed process-lifetime array of
the built-in production Apple root certificates. Callers must not release or
mutate it without first taking their own retain. It is not an OSStatus API and
has no output parameter or null-argument error case. It does not import package
certificates or alter trust policy.

The compatibility entry point follows Apple's newer unified-trust implementation:
[SecTrust.c](https://github.com/apple-oss-distributions/Security/blob/main/OSX/sec/Security/SecTrust.c)
delegates directly to `SecGetAppleTrustAnchors(false)`, with the no-argument
declaration in
[SecTrustPriv.h](https://github.com/apple-oss-distributions/Security/blob/main/trust/headers/SecTrustPriv.h).
The vendored release predates that entry point but already contains the same
process-static production-root helper and genuine embedded root material.