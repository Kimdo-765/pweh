/* SPDX-License-Identifier: MIT
 * CDC0 프로토콜 + CDC1 예약 채널. 다른 USB class는 기술하지 않는다. */
#include "profile.h"
const tusb_desc_device_t pweh_usb_device_descriptor = {
    .bLength=18,.bDescriptorType=TUSB_DESC_DEVICE,.bcdUSB=0x0200,
    .bDeviceClass=TUSB_CLASS_MISC,.bDeviceSubClass=MISC_SUBCLASS_COMMON,
    .bDeviceProtocol=MISC_PROTOCOL_IAD,.bMaxPacketSize0=64,
    .idVendor=0x303a,.idProduct=0x4002,.bcdDevice=0x0100,
    .iManufacturer=1,.iProduct=2,.iSerialNumber=3,.bNumConfigurations=1
};
const uint32_t pweh_usb_device_descriptor_size=sizeof(pweh_usb_device_descriptor);
const uint8_t pweh_usb_configuration_descriptor[] = {
    TUD_CONFIG_DESCRIPTOR(1,4,0,TUD_CONFIG_DESC_LEN+2*TUD_CDC_DESC_LEN,0,100),
    TUD_CDC_DESCRIPTOR(0,4,0x81,8,0x02,0x82,64),
    TUD_CDC_DESCRIPTOR(2,4,0x83,8,0x04,0x84,64)
};
const uint32_t pweh_usb_configuration_descriptor_size=sizeof(pweh_usb_configuration_descriptor);
_Static_assert(sizeof(pweh_usb_device_descriptor)==18,"device descriptor 크기");
_Static_assert(sizeof(pweh_usb_configuration_descriptor)==141,"CDC 2개 config 크기");
