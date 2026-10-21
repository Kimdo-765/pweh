/* SPDX-License-Identifier: MIT
 * probe-hello: USB 수명주기와 wire만 연결한다. 대상 핀·UART·SPI·무선은 초기화하지 않는다. */
#include <stdatomic.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_app_desc.h"
#include "esp_attr.h"
#include "esp_chip_info.h"
#include "esp_idf_version.h"
#include "esp_mac.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_task_wdt.h"
#include "bootloader_random.h"
#include "tinyusb.h"
#include "tinyusb_default_config.h"
#include "tinyusb_cdc_acm.h"
#include "device/dcd.h"
#include "pweh_session.h"
#include "pweh_build_identity.h"
#include "profile.h"

/* 모든 상태는 한 worker가 소유한다. ISR/callback은 원자적 사건 비트만 쓴다. */
static pweh_probe probe;
static atomic_uint events;
static atomic_uint dtr;
_Static_assert(ATOMIC_INT_LOCK_FREE==2,"ISR 사건 latch는 lock-free여야 한다");
typedef struct {size_t size,offset;uint8_t bytes[PWEH_MAX_WIRE];} tx_frame;
static tx_frame tx[2];
static unsigned tx_head,tx_count;

static void IRAM_ATTR latch(pweh_release_reason reason){atomic_fetch_or(&events,1u<<(unsigned)reason);}

/* TinyUSB umount는 bus reset 때 호출되지 않아 queue hook도 관찰한다. ISR에서 I/O 금지. */
void IRAM_ATTR tud_event_hook_cb(uint8_t rhport,uint32_t eventid,bool in_isr){
    (void)rhport;(void)in_isr;
    if(eventid==DCD_EVENT_BUS_RESET)latch(PWEH_RELEASE_USB_RESET);
}
static void lifecycle(tinyusb_event_t *event,void *arg){
    (void)arg;
    if(event->id==TINYUSB_EVENT_DETACHED)latch(PWEH_RELEASE_USB_DETACH);
    else if(event->id==TINYUSB_EVENT_SUSPENDED)latch(PWEH_RELEASE_USB_SUSPEND);
}
static void line_state(int itf,cdcacm_event_t *event){
    if(itf!=0)return;
    bool next=event->line_state_changed_data.dtr;
    if(atomic_exchange(&dtr,next)&&!next)latch(PWEH_RELEASE_DTR);
}
static void clear_tx(void){
    tx_head=tx_count=0;memset(tx,0,sizeof(tx));tud_cdc_n_write_clear(0);
}
static void released(void *user,pweh_release_reason reason){
    (void)user;(void)reason;
    /* 이 profile은 claim한 target pad가 0개다. USB/예약 핀의 GPIO 상태를 바꾸지 않는다. */
    clear_tx();
}
static bool enqueue(void *user,const uint8_t *data,size_t size){
    (void)user;
    if(size>PWEH_MAX_WIRE||tx_count==2)return false;
    tx_frame *f=&tx[(tx_head+tx_count)%2];memcpy(f->bytes,data,size);f->size=size;f->offset=0;tx_count++;return true;
}
static void drain_tx(void){
    if(!tx_count)return;
    tx_frame *f=&tx[tx_head];
    size_t n=tinyusb_cdcacm_write_queue(TINYUSB_CDC_ACM_0,f->bytes+f->offset,f->size-f->offset);
    if(n>f->size-f->offset){pweh_probe_release(&probe,PWEH_RELEASE_TRANSPORT);return;}
    f->offset+=n;
    esp_err_t err=tinyusb_cdcacm_write_flush(TINYUSB_CDC_ACM_0,0);
    if(err!=ESP_OK&&err!=ESP_ERR_NOT_FINISHED){pweh_probe_release(&probe,PWEH_RELEASE_TRANSPORT);return;}
    if(f->offset==f->size){memset(f,0,sizeof(*f));tx_head=(tx_head+1)%2;tx_count--;}
}
static void apply_events(void){
    unsigned pending=atomic_exchange(&events,0);
    if(!pending)return;
    clear_tx();tud_cdc_n_read_flush(0);tud_cdc_n_read_flush(1);
    for(unsigned r=PWEH_RELEASE_USB_RESET;r<=PWEH_RELEASE_DTR;r++)
        if(pending&(1u<<r))pweh_probe_transport_reset(&probe,(pweh_release_reason)r);
}
static void worker(void *arg){
    (void)arg;uint8_t bytes[256];
    if(esp_task_wdt_add(NULL)!=ESP_OK){probe.closed=true;vTaskDelete(NULL);return;}
    for(;;){
        if(esp_task_wdt_reset()!=ESP_OK){pweh_probe_release(&probe,PWEH_RELEASE_INTERNAL);probe.closed=true;}
        apply_events();pweh_probe_poll(&probe,(uint64_t)esp_timer_get_time()/1000);
        /* 연속 입력도 이 예산 뒤 poll로 돌아오므로 만료 검사가 굶지 않는다. */
        for(unsigned i=0;i<8;i++){
            size_t n=0;
            if(tinyusb_cdcacm_read(TINYUSB_CDC_ACM_0,bytes,sizeof(bytes),&n)!=ESP_OK){pweh_probe_release(&probe,PWEH_RELEASE_TRANSPORT);break;}
            if(!n)break;
            if(atomic_load(&events)){apply_events();break;}
            (void)pweh_probe_feed(&probe,bytes,n,(uint64_t)esp_timer_get_time()/1000);
        }
        /* CDC1은 예약 채널: 받은 데이터는 해석·반송하지 않는다. */
        tud_cdc_n_read_flush(1);drain_tx();vTaskDelay(pdMS_TO_TICKS(10));
    }
}
static uint16_t reset_reason(void){
    switch(esp_reset_reason()){
    case ESP_RST_POWERON:return 1;case ESP_RST_SW:return 2;case ESP_RST_PANIC:return 3;
    case ESP_RST_INT_WDT:case ESP_RST_TASK_WDT:case ESP_RST_WDT:return 4;
    case ESP_RST_BROWNOUT:return 5;case ESP_RST_DEEPSLEEP:return 6;case ESP_RST_EXT:return 7;
    default:return 0;
    }
}
void app_main(void){
    pweh_identity identity={.fw_name=PWEH_FW_NAME,.fw_version=PWEH_FW_VERSION,
        .profile=PWEH_BUILD_PROFILE,.board=PWEH_BUILD_BOARD,.git_commit=PWEH_SOURCE_COMMIT,
        .idf_version=IDF_VER,.usb_product="PWEH espprobe",.vid=0x303a,.pid=0x4002,
        .hb_ms=1000,.chip_model=1,.chip_known=3,.policy=pweh_probe_policy_blob};
    identity.policy_size=pweh_probe_policy_blob_size;identity.reset_reason=reset_reason();
    esp_chip_info_t chip;esp_chip_info(&chip);identity.revision=chip.revision;
    const esp_app_desc_t *app=esp_app_get_description();memcpy(identity.app_elf_sha256,app->app_elf_sha256,32);
    const esp_partition_t *part=esp_ota_get_running_partition();
    if(!part||esp_partition_get_sha256(part,identity.image_sha256)!=ESP_OK||esp_read_mac(identity.base_mac,ESP_MAC_BASE)!=ESP_OK)return;
    bootloader_random_enable();esp_fill_random(identity.boot_id,sizeof(identity.boot_id));bootloader_random_disable();
    pweh_hal hal={.emit=enqueue,.release=released};if(!pweh_probe_init(&probe,&identity,&hal))return;
    tinyusb_config_t config=TINYUSB_DEFAULT_CONFIG(lifecycle,NULL);
    if(pweh_usb_device_descriptor_size!=18||pweh_usb_configuration_descriptor_size!=141)return;
    config.descriptor.device=&pweh_usb_device_descriptor;
    config.descriptor.full_speed_config=pweh_usb_configuration_descriptor;
    if(tinyusb_driver_install(&config)!=ESP_OK)return;
    const tinyusb_config_cdcacm_t cdc0={.cdc_port=TINYUSB_CDC_ACM_0,.callback_line_state_changed=line_state};
    const tinyusb_config_cdcacm_t cdc1={.cdc_port=TINYUSB_CDC_ACM_1};
    if(tinyusb_cdcacm_init(&cdc0)!=ESP_OK||tinyusb_cdcacm_init(&cdc1)!=ESP_OK){(void)tinyusb_driver_uninstall();return;}
    if(xTaskCreate(worker,"pweh-probe",16384,NULL,5,NULL)!=pdPASS){
        (void)tinyusb_cdcacm_deinit(0);(void)tinyusb_cdcacm_deinit(1);(void)tinyusb_driver_uninstall();
    }
}
