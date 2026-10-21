/* SPDX-License-Identifier: MIT
 * 전송 독립 상태기계. 실제 GPIO/USB 함수는 HAL adapter에만 둔다. */
#ifndef PWEH_SESSION_H
#define PWEH_SESSION_H
#include "pweh_protocol.h"
typedef enum { PWEH_RELEASE_NONE=0,PWEH_RELEASE_BOOT=1,PWEH_RELEASE_REQUEST=2,PWEH_RELEASE_BYE=3,PWEH_RELEASE_ABORT=4,
 PWEH_RELEASE_HEARTBEAT=5,PWEH_RELEASE_USB_RESET=6,PWEH_RELEASE_USB_DETACH=7,PWEH_RELEASE_USB_SUSPEND=8,
 PWEH_RELEASE_DTR=9,PWEH_RELEASE_TRANSPORT=10,PWEH_RELEASE_INTERNAL=11,PWEH_RELEASE_SEQUENCE=12,
 PWEH_RELEASE_CLOCK=13,PWEH_RELEASE_HOST=14 } pweh_release_reason;
typedef struct {
    char fw_name[33],fw_version[33],profile[33],board[49],git_commit[41],idf_version[33],usb_product[33];
    uint8_t image_sha256[32],app_elf_sha256[32],base_mac[6],boot_id[16];
    uint16_t revision,flash_mv,vid,pid,reset_reason,hb_ms;
    uint32_t psram_bytes;
    uint8_t chip_model,chip_known;
    const uint8_t *policy;size_t policy_size;
} pweh_identity;
typedef struct {void *user;bool (*emit)(void *,const uint8_t *,size_t);void (*release)(void *,pweh_release_reason);} pweh_hal;
typedef struct {uint32_t seq;size_t request_size,response_size;uint8_t request[PWEH_MAX_WIRE],response[PWEH_MAX_WIRE];} pweh_cache;
typedef struct {
    pweh_identity identity;pweh_hal hal;
    uint32_t session,usb_session,last_req_seq,last_hb_seq,hello_seq,token;
    uint64_t now_ms,deadline_ms,rx_frames,tx_frames,invalid_frames,replay_hits,requests_executed,heartbeats_accepted,release_count;
    pweh_release_reason last_release_reason;
    bool closed,discarding;size_t rx_size,cache_next;
    uint8_t rx[PWEH_MAX_WIRE],out[PWEH_MAX_WIRE];
    pweh_frame frame,response;
    pweh_cache cache[4],hello,tombstone;
} pweh_probe;
bool pweh_probe_init(pweh_probe *,const pweh_identity *,const pweh_hal *);
pweh_result pweh_probe_feed(pweh_probe *,const uint8_t *,size_t,uint64_t);
void pweh_probe_poll(pweh_probe *,uint64_t);
void pweh_probe_release(pweh_probe *,pweh_release_reason);
void pweh_probe_transport_reset(pweh_probe *,pweh_release_reason);
#endif
