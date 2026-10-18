/*
 * busybox_stub.c - PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE
 *
 * pweh.mocktarget 합성 펌웨어의 /bin/busybox (및 mtd-utils/u-boot-tools 자리) 대용 바이너리.
 * 실제 BusyBox 가 아니다. 버전 식별(정적 분석)을 위한 배너 문자열과 애플릿 이름만 담는다.
 * 시뮬레이터의 셸은 이 바이너리를 실행하지 않고 파이썬으로 흉내 낸다.
 */
#include <stdio.h>
#include <string.h>

#ifndef PWEH_BUSYBOX_BANNER
#define PWEH_BUSYBOX_BANNER "BusyBox v1.24.1 (2020-01-01 00:00:00 CST)"
#endif

const char pweh_marker[] = "PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE";
const char bb_banner[] = PWEH_BUSYBOX_BANNER;

static const char *const applet_names[] = {
    "ash", "cat", "dd", "echo", "flash_eraseall", "hexdump", "ifconfig", "init", "login", "ls",
    "md5sum", "mount", "ps", "sh", "telnetd", "uname", NULL
};

int main(int argc, char **argv)
{
    const char *name = argc > 0 && argv[0] ? strrchr(argv[0], '/') : NULL;
    int i;
    name = name ? name + 1 : (argc > 0 && argv[0] ? argv[0] : "busybox");
    if (strcmp(name, "busybox") == 0) {
        printf("%s multi-call binary.\n", bb_banner);
        printf("(%s)\n\nCurrently defined functions:\n\t", pweh_marker);
        for (i = 0; applet_names[i]; i++)
            printf("%s%s", i ? ", " : "", applet_names[i]);
        printf("\n");
        return 0;
    }
    fprintf(stderr, "%s: synthetic stub (%s)\n", name, pweh_marker);
    return 1;
}
