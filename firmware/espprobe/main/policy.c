/* SPDX-License-Identifier: MIT
 * 실제 HELLO가 참조하는 정책 TLV를 ELF checker도 읽는다. GPIO claim은 없다. */
#include "profile.h"
const uint8_t pweh_probe_policy_blob[] = {
    19,0,4,0, 0,0,0,0,
    20,0,6,0, 0,16,232,3,0,0,
    21,0,24,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    22,0,1,0, 255,
    23,0,1,0, 0,
    24,0,0,0,
    25,0,1,0, 0,
    26,0,4,0, 0,0,0,0
};
const uint32_t pweh_probe_policy_blob_size = sizeof(pweh_probe_policy_blob);
_Static_assert(sizeof(pweh_probe_policy_blob)==73,"정책 TLV 크기");
