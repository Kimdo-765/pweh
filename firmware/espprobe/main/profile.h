/* SPDX-License-Identifier: MIT */
#ifndef PWEH_PROFILE_H
#define PWEH_PROFILE_H
#include <stdint.h>
#include "tusb.h"
extern const tusb_desc_device_t pweh_usb_device_descriptor;
extern const uint32_t pweh_usb_device_descriptor_size;
extern const uint8_t pweh_usb_configuration_descriptor[];
extern const uint32_t pweh_usb_configuration_descriptor_size;
extern const uint8_t pweh_probe_policy_blob[];
extern const uint32_t pweh_probe_policy_blob_size;
#endif
