/* 합성 host HAL: stdin의 bounded 명령만 읽는다. 실제 장치/USB/핀은 없다. */
#include "pweh_session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct {uint64_t before;pweh_probe probe;uint64_t after;} guarded;
static uint8_t output[PWEH_MAX_WIRE];static size_t output_size;static unsigned releases;static bool emit_ok=true;
static bool emit(void *user,const uint8_t *data,size_t n){
    (void)user;if(!emit_ok)return false;if(n>sizeof(output))abort();memcpy(output,data,n);output_size=n;return true;
}
static void release(void *user,pweh_release_reason reason){(void)user;(void)reason;releases++;}
static void printhex(const uint8_t *data,size_t n){for(size_t i=0;i<n;i++)printf("%02x",data[i]);puts("");}
static int digit(char c){if(c>='0'&&c<='9')return c-'0';if(c>='a'&&c<='f')return c-'a'+10;return -1;}
static size_t parse(const char *hex,uint8_t *out,size_t cap){
    size_t n=strcspn(hex,"\r\n");if(n%2||n/2>cap)return SIZE_MAX;
    for(size_t i=0;i<n;i+=2){int a=digit(hex[i]),b=digit(hex[i+1]);if(a<0||b<0)return SIZE_MAX;out[i/2]=(uint8_t)((a<<4)|b);}return n/2;
}
int main(int argc,char **argv){
    if(argc!=2)return 2;
    pweh_identity identity={.fw_name="PWEH espprobe",.fw_version="0.1.0",.profile="probe-hello",
        .board="esp32s3-devkitc1-hello",.git_commit="0000000000000000000000000000000000000000",
        .idf_version="simulator",.usb_product="PWEH espprobe",.base_mac={2,0,0,0,0,1},
        .vid=12346,.pid=16386,.reset_reason=1,.hb_ms=1000,.chip_model=1,.chip_known=3};
    uint8_t policy[73]={19,0,4,0,0,0,0,0,20,0,6,0,0,16,232,3,0,0,21,0,24,0};
    const uint8_t tail[]={22,0,1,0,255,23,0,1,0,0,24,0,0,0,25,0,1,0,0,26,0,4,0,0,0,0,0};
    memcpy(policy+46,tail,sizeof(tail));identity.policy=policy;identity.policy_size=sizeof(policy);
    memset(identity.image_sha256,17,32);memset(identity.app_elf_sha256,34,32);
    pweh_hal hal={.emit=emit,.release=release};
    guarded.before=guarded.after=UINT64_C(0x12345678abcdef01);
    if(!pweh_probe_init(&guarded.probe,&identity,&hal))return 3;
    char line[33000];uint8_t bytes[16384];pweh_frame frame;
    while(fgets(line,sizeof(line),stdin)){
        output_size=0;
        if(!strcmp(argv[1],"codec")){
            size_t n=parse(line,bytes,sizeof(bytes)),written=0;
            if(n==SIZE_MAX||pweh_frame_decode(bytes,n,&frame)!=PWEH_OK||pweh_frame_encode(&frame,output,sizeof(output),&written)!=PWEH_OK)puts("ERR");
            else printhex(output,written);
        } else if(!strcmp(argv[1],"session")){
            char *end=NULL;unsigned long long number=strtoull(line+2,&end,10);
            switch(line[0]){
            case 'W': {size_t n=(*end==' ')?parse(end+1,bytes,sizeof(bytes)):SIZE_MAX;
                if(n==SIZE_MAX||pweh_probe_feed(&guarded.probe,bytes,n,(uint64_t)number)!=PWEH_OK)puts("ERR");else printhex(output,output_size);break;}
            case 'P': pweh_probe_poll(&guarded.probe,(uint64_t)number);puts("OK");break;
            case 'E': pweh_probe_transport_reset(&guarded.probe,(pweh_release_reason)number);puts("OK");break;
            case 'F': emit_ok=number!=0;puts("OK");break;
            case 'S': printf("%u %u %u %u %llu %u %u %llu %llu\n",guarded.probe.session,guarded.probe.usb_session,
                guarded.probe.last_req_seq,guarded.probe.last_hb_seq,(unsigned long long)guarded.probe.deadline_ms,
                (unsigned)guarded.probe.last_release_reason,releases,(unsigned long long)guarded.probe.requests_executed,
                (unsigned long long)guarded.probe.heartbeats_accepted);break;
            default:return 4;
            }
        }else return 2;
        if(guarded.before!=UINT64_C(0x12345678abcdef01)||guarded.after!=UINT64_C(0x12345678abcdef01))abort();
    }
    return ferror(stdin)?5:0;
}
