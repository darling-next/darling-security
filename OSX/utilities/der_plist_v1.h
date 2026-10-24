/*
 * V1 DER entitlements serialization, separate from the legacy
 * CFPropertyListCreateDERData (SET) format.
 */
#ifndef _DER_PLIST_V1_H_
#define _DER_PLIST_V1_H_

#include <CoreFoundation/CoreFoundation.h>
#include <utilities/SecCFError.h>

CFDataRef CFPropertyListCreateDEREntitlementsV1(CFAllocatorRef allocator,
                                                CFPropertyListRef plist,
                                                CFErrorRef *error);

/* Inner b0 dictionary only, matching native `derq query -f xml` without --raw. */
CFDataRef CFPropertyListCreateDEREntitlementsV1Inner(CFAllocatorRef allocator,
                                                     CFPropertyListRef plist,
                                                     CFErrorRef *error);

#endif /* _DER_PLIST_V1_H_ */
