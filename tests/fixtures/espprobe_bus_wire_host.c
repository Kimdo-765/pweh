/* 실제 common HELLO·버스·wire를 잇는 합성 전용 driver. 실제 장치 I/O는 없다. */
#include "probe_bus_wire.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CANARY UINT64_C(0x19d34e71ab82cd65)
#define OUTPUT_MAX 65536u
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"fixture invariant %u\n",(unsigned)__LINE__); exit(70); } } while (0)
static struct { uint64_t before; probe_bus_ctx value; uint64_t after; } bus;
static struct { uint64_t before; probe_bus_wire_ctx value; uint64_t after; } wire;
static struct { uint64_t before; pweh_probe value; uint64_t after; } common;
static probe_bus_binding binding;
static probe_bus_wiring wiring;
static struct {
    uint8_t out[OUTPUT_MAX], sfdp[4096]; size_t used;
    uint64_t now, transactions, spi_bytes, reads, deliveries, aborts, claims;
    uint64_t emits, data, done, nested, stops, nacks;
    unsigned position, opcode, address_bytes, dummy_bytes, read_index, i2c_writes;
    unsigned mode, fault_delivery; uint32_t address, i2c_address;
    uint16_t mv; bool cs, wire_ready;
} f;

static void canaries(void) {
    CHECK(bus.before==CANARY && bus.after==CANARY);
    CHECK(wire.before==CANARY && wire.after==CANARY);
    CHECK(common.before==CANARY && common.after==CANARY);
}
static void put64(uint8_t *out,uint64_t v) {
    for(unsigned i=0;i<8;i++) out[i]=(uint8_t)(v>>(8*i));
}
static uint64_t get64(const uint8_t *in) {
    uint64_t v=0; for(unsigned i=0;i<8;i++) v|=(uint64_t)in[i]<<(8*i); return v;
}
static bool emit(void *user,const uint8_t *data,size_t n) {
    (void)user; pweh_frame frame;
    CHECK(pweh_frame_decode(data,n,&frame)==PWEH_OK);
    if(f.wire_ready && frame.type==4 && f.mode==4 && f.deliveries==f.fault_delivery) return false;
    CHECK(n<=OUTPUT_MAX-f.used); memcpy(f.out+f.used,data,n); f.used+=n; f.emits++;
    if(f.wire_ready && frame.type==4) {
        f.data++;
        if(f.mode==5) {
            size_t before=f.used;
            CHECK(probe_bus_wire_feed(&wire.value,data,n,f.now)==PWEH_INVALID);
            CHECK(probe_bus_wire_poll(&wire.value,f.now)==PWEH_INVALID);
            CHECK(f.used==before); f.nested+=2;
        }
    }
    if(f.wire_ready && frame.type==3 && frame.op==0x12) f.done++;
    return true;
}
static bool clock_ms(void *user,uint64_t *out) { (void)user; *out=f.now; return true; }
static bool vref(void *user,probe_vref_sample *out) {
    (void)user; *out=(probe_vref_sample){true,f.mv,f.now}; return true;
}
static bool claim(void *user,const probe_bus_wiring *w) {
    (void)user; CHECK(w->kind==wiring.kind); f.claims++; return true;
}
static bool cs(void *user,bool active) {
    (void)user; CHECK(f.aborts==0);
    if(active) { CHECK(!f.cs); f.position=0; f.address=0; f.read_index=0; f.transactions++; }
    else CHECK(f.cs);
    f.cs=active; return true;
}
static uint8_t memory(uint32_t address) {
    uint8_t result=(uint8_t)address;
    if(f.mode==1 && bus.value.pass_index==1 && address==bus.value.plan.offset) result^=1;
    return result;
}
static bool spi_byte(void *user,uint8_t tx,uint8_t *rx) {
    (void)user; CHECK(f.cs && !f.aborts); f.spi_bytes++; *rx=0;
    if(f.position==0) {
        f.opcode=tx;
        f.address_bytes=(tx==0x13 || tx==0x0c)?4:(tx==3 || tx==0x0b || tx==0x5a)?3:0;
        f.dummy_bytes=(tx==0x0b || tx==0x0c || tx==0x5a)?1:0;
    } else if(f.position<=f.address_bytes) f.address=(f.address<<8)|tx;
    else if(f.position>f.address_bytes+f.dummy_bytes) {
        unsigned index=f.read_index++;
        if(f.opcode==0x9f) { const uint8_t id[3]={0xef,0x40,0x19}; CHECK(index<3); *rx=id[index]; }
        else if(f.opcode==5) *rx=0x1c;
        else if(f.opcode==0x5a) { CHECK((uint64_t)f.address+index<sizeof(f.sfdp)); *rx=f.sfdp[f.address+index]; }
        else { CHECK(f.opcode==3 || f.opcode==0x0b || f.opcode==0x13 || f.opcode==0x0c); *rx=memory(f.address+index); }
    }
    f.position++; return true;
}
static bool i2c_start(void *user,bool repeated) {
    (void)user; CHECK(!f.aborts);
    if(!repeated) { f.i2c_writes=0; f.i2c_address=0; f.read_index=0; f.transactions++; }
    return true;
}
static bool i2c_write(void *user,uint8_t value,bool *acked) {
    (void)user; CHECK(!f.aborts);
    if(f.i2c_writes>0 && f.i2c_writes<=wiring.bus.i2c.address_width) f.i2c_address=(f.i2c_address<<8)|value;
    f.i2c_writes++; *acked=true; return true;
}
static bool i2c_read(void *user,bool ack,uint8_t *out) {
    (void)user; CHECK(!f.aborts); *out=memory(f.i2c_address+f.read_index++);
    f.reads++; if(!ack) f.nacks++; return true;
}
static bool i2c_stop(void *user) { (void)user; CHECK(!f.aborts); f.stops++; return true; }
static bool deliver(void *user,const probe_bus_chunk *chunk) {
    (void)user; f.deliveries++;
    bool ok=probe_bus_wire_deliver(&wire.value,chunk);
    /* emit 이후의 실제 core guard가 관찰한다. callback 안에서 release하지 않는다. */
    if(ok && f.deliveries==f.fault_delivery) {
        if(f.mode==2) f.mv=2999;
        if(f.mode==3) f.now=bus.value.deadline_ms;
    }
    return ok;
}
static void abort_bus(void *user,uint64_t mask,pweh_release_reason reason) {
    (void)user; CHECK(mask>0 && reason!=PWEH_RELEASE_NONE);
    CHECK(bus.value.state==PROBE_BUS_STATE_RELEASED && bus.value.credit==0);
    f.aborts++; CHECK(f.aborts==1); f.cs=false;
}
static void common_release(void *user,pweh_release_reason reason) { (void)user; (void)reason; }
static void hello(void) {
    pweh_identity id={.fw_name="PWEH espprobe",.fw_version="0.1.0",.profile="probe-hello",
        .board="esp32s3-devkitc1-hello",.git_commit="0000000000000000000000000000000000000000",
        .idf_version="simulator",.usb_product="PWEH espprobe",.base_mac={2,0,0,0,0,1},
        .vid=12346,.pid=16386,.reset_reason=1,.hb_ms=1000,.chip_model=1,.chip_known=3};
    static uint8_t policy[73]={19,0,4,0,0,0,0,0,20,0,6,0,0,16,232,3,0,0,21,0,24,0};
    const uint8_t tail[]={22,0,1,0,255,23,0,1,0,0,24,0,0,0,25,0,1,0,0,26,0,4,0,0,0,0,0};
    memcpy(policy+46,tail,sizeof(tail)); id.policy=policy; id.policy_size=sizeof(policy);
    memset(id.boot_id,7,16); memset(id.image_sha256,17,32); memset(id.app_elf_sha256,34,32);
    pweh_hal h={.emit=emit,.release=common_release}; CHECK(pweh_probe_init(&common.value,&id,&h));
    pweh_frame request={.version=1,.type=1,.op=1,.seq=1,.length=20};
    request.payload[0]=1; request.payload[2]=16;
    for(unsigned i=0;i<16;i++) request.payload[i+4]=(uint8_t)i;
    uint8_t encoded[PWEH_MAX_WIRE]; size_t n=0; pweh_frame response;
    CHECK(pweh_frame_encode(&request,encoded,sizeof(encoded),&n)==PWEH_OK);
    CHECK(pweh_probe_feed(&common.value,encoded,n,f.now)==PWEH_OK);
    CHECK(pweh_frame_decode(f.out,f.used,&response)==PWEH_OK);
    CHECK(response.session>0 && response.flags==0 && pweh_get16(response.payload)==0);
    binding=(probe_bus_binding){.session=common.value.session,.usb_session=common.value.usb_session,
        .hello_seq=common.value.hello_seq,.last_hb_seq=common.value.last_hb_seq,.hb_ms=id.hb_ms,
        .now_ms=common.value.now_ms,.deadline_ms=common.value.deadline_ms};
    memcpy(binding.boot_id,common.value.identity.boot_id,16);
}
static void sfdp(void) {
    memcpy(f.sfdp,"SFDP",4); f.sfdp[4]=6; f.sfdp[5]=1; f.sfdp[6]=1; f.sfdp[7]=0xff;
    const uint8_t bfpt[]={0,6,1,9,0x40,0,0,0xff}, bait[]={0x84,1,1,2,0x80,0,0,0xff};
    memcpy(f.sfdp+8,bfpt,8); memcpy(f.sfdp+16,bait,8);
    pweh_put32(f.sfdp+0x40,UINT32_C(1)<<17);
    pweh_put32(f.sfdp+0x44,0x0fffffffu); pweh_put32(f.sfdp+0x80,3);
}
static void response(pweh_result result) {
    uint8_t header[8]; canaries(); CHECK(f.used<=OUTPUT_MAX);
    pweh_put32(header,(uint32_t)result); pweh_put32(header+4,(uint32_t)f.used);
    CHECK(fwrite(header,1,8,stdout)==8); CHECK(fwrite(f.out,1,f.used,stdout)==f.used);
    CHECK(fflush(stdout)==0); f.used=0;
}
static void stats(void) {
    uint64_t values[]={bus.value.state,bus.value.credit,bus.value.deadline_ms,bus.value.last_hb_seq,
        f.transactions,f.spi_bytes,f.reads,f.deliveries,f.aborts,f.claims,f.emits,f.data,f.done,
        f.nested,f.stops,f.nacks};
    for(unsigned i=0;i<16;i++) put64(f.out+8*i,values[i]); f.used=128;
}
int main(int argc,char **argv) {
    if(argc!=5) return 2;
    unsigned kind=(unsigned)strtoul(argv[1],NULL,10),width=(unsigned)strtoul(argv[2],NULL,10);
    f.mode=(unsigned)strtoul(argv[3],NULL,10); f.fault_delivery=(unsigned)strtoul(argv[4],NULL,10);
    CHECK(kind<=1 && width>=1 && width<=2 && f.mode<=5 && f.fault_delivery<=4096);
    f.now=100; f.mv=3300; bus.before=bus.after=wire.before=wire.after=common.before=common.after=CANARY;
    hello(); sfdp();
    wiring=(probe_bus_wiring){.kind=kind?PROBE_I2C_EEPROM_READ:PROBE_SPI_READ_RANGE,.declared_mv=3300,.allowed_mask=15};
    if(kind) wiring.bus.i2c=(probe_i2c_wiring){.scl=0,.sda=1,.addr7=0x50,.address_width=(uint8_t)width,.capacity=width==1?256:65536};
    else wiring.bus.spi=(probe_spi_pins){.cs=0,.sck=1,.mosi=2,.miso=3};
    probe_bus_hal hal={.clock_ms=clock_ms,.read_vref=vref,.claim=claim,.spi_cs=cs,.spi_byte=spi_byte,
        .i2c_start=i2c_start,.i2c_write_byte=i2c_write,.i2c_read_byte=i2c_read,.i2c_stop=i2c_stop,
        .deliver_chunk=deliver,.abort=abort_bus};
    CHECK(probe_bus_init(&bus.value,&hal)==PROBE_BUS_OK);
    CHECK(probe_bus_bind(&bus.value,&binding)==PROBE_BUS_OK);
    CHECK(probe_bus_claim(&bus.value,&wiring,f.now)==PROBE_BUS_OK);
    CHECK(probe_bus_wire_init(&wire.value,&bus.value,emit,NULL)); f.wire_ready=true;
    response(PWEH_OK);
    unsigned controls=0; uint8_t header[13],data[16384];
    while(controls++<8192) {
        size_t got=fread(header,1,sizeof(header),stdin);
        if(got==0 && feof(stdin)) break;
        CHECK(got==sizeof(header)); uint32_t size=pweh_get32(header+9); CHECK(size<=sizeof(data));
        CHECK(fread(data,1,size,stdin)==size); f.now=get64(header+1); pweh_result result=PWEH_OK;
        switch(header[0]) {
        case 'W': result=probe_bus_wire_feed(&wire.value,data,size,f.now); break;
        case 'P': CHECK(size==0); result=probe_bus_wire_poll(&wire.value,f.now); break;
        case 'S': CHECK(size==0); stats(); break;
        case 'H': result=pweh_probe_feed(&common.value,data,size,f.now); break;
        case 'Q': CHECK(size==0); probe_bus_wire_abort(&wire.value,PWEH_RELEASE_HOST); response(PWEH_OK); return 0;
        default: return 2;
        }
        response(result);
    }
    probe_bus_wire_abort(&wire.value,PWEH_RELEASE_HOST); canaries(); return controls>=8192?2:0;
}
