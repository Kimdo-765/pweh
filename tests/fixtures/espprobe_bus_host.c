/* 합성 버스 HAL. 공통 HELLO와 실제 버스 코어만 연결하며 장치 I/O는 없다. */
#include "probe_bus.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CANARY UINT64_C(0x19d34e71ab82cd65)
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "fixture invariant at line %u\n", (unsigned)__LINE__); exit(70); } } while (0)
enum { CLAIM=1, CS_ON, CS_OFF, SPI_BYTE, START, RESTART, WRITE, READ_ACK, READ_NACK, STOP, DELIVER, ABORT };
enum { FAIL=1, EXPIRE, LOW_VREF, STALE_VREF, FUTURE_VREF, INVALID_VREF, BACKWARD, RELEASE, REENTER, NACK, HIGH_VREF };
typedef struct { unsigned code, value; } event;
static struct { uint64_t before; probe_bus_ctx ctx; uint64_t after; } guarded;
static struct { uint64_t before; pweh_probe probe; uint64_t after; } common;
static struct { uint64_t before; probe_bus_chunk chunk; uint64_t after; } output;
static struct {
    event events[4096]; unsigned used, phases, clocks, vrefs, aborts, deliveries, claims, after_abort;
    unsigned fault_phase, fault_clock, fault_vref, effect, nested_checks, i2c_writes;
    unsigned position, opcode, address_bytes, dummy_bytes, read_index;
    unsigned transaction_count, opcodes[128];
    uint32_t address, i2c_address;
    uint64_t now, abort_mask;
    bool invalid_vref, stale_vref, future_vref, clock_failed, vref_failed, cs;
    uint16_t mv;
    uint8_t sfdp[4096], wire[PWEH_MAX_WIRE]; size_t wire_size;
    probe_bus_chunk delivered[8];
} fake;
static probe_bus_binding binding;
static probe_bus_wiring wiring;
static probe_read_plan plan;

static void canaries(void) {
    CHECK(guarded.before==CANARY && guarded.after==CANARY);
    CHECK(common.before==CANARY && common.after==CANARY);
    CHECK(output.before==CANARY && output.after==CANARY);
}
static bool zero(const void *data, size_t n) {
    const unsigned char *p=data; for(size_t i=0;i<n;i++) if(p[i]) return false; return true;
}
static bool effect(unsigned which) {
    switch(which) {
    case FAIL: return false;
    case EXPIRE: fake.now=guarded.ctx.deadline_ms; break;
    case LOW_VREF: fake.mv=2999; break;
    case HIGH_VREF: fake.mv=3601; break;
    case STALE_VREF: fake.stale_vref=true; break;
    case FUTURE_VREF: fake.future_vref=true; break;
    case INVALID_VREF: fake.invalid_vref=true; break;
    case BACKWARD: fake.now=99; break;
    case RELEASE: probe_bus_release(&guarded.ctx,PWEH_RELEASE_USB_DETACH); break;
    case REENTER: {
        probe_bus_chunk nested;
        CHECK(probe_bus_step(&guarded.ctx,fake.now,&nested)==PROBE_BUS_BUSY);
        CHECK(probe_bus_begin(&guarded.ctx,200,&plan,fake.now)==PROBE_BUS_BUSY);
        CHECK(probe_bus_claim(&guarded.ctx,&wiring,fake.now)==PROBE_BUS_BUSY);
        fake.nested_checks+=3; break;
    }
    default: break;
    }
    return true;
}
static bool phase(unsigned code,unsigned value) {
    CHECK(fake.used<sizeof(fake.events)/sizeof(fake.events[0]));
    if(fake.aborts) fake.after_abort++;
    fake.events[fake.used++]=(event){code,value}; fake.phases++;
    return fake.fault_phase!=fake.phases || effect(fake.effect);
}
static bool clock_ms(void *u,uint64_t *out) {
    (void)u; fake.clocks++;
    if(fake.fault_clock==fake.clocks && !effect(fake.effect)) return false;
    *out=fake.now; return !fake.clock_failed;
}
static bool read_vref(void *u,probe_vref_sample *out) {
    (void)u; fake.vrefs++;
    if(fake.fault_vref==fake.vrefs && !effect(fake.effect)) return false;
    out->valid=!fake.invalid_vref; out->millivolts=fake.mv;
    out->sampled_at_ms=fake.future_vref?fake.now+1:fake.stale_vref?fake.now-2:fake.now;
    return !fake.vref_failed;
}
static bool claim(void *u,const probe_bus_wiring *w) {
    (void)u; CHECK(w->kind==wiring.kind); fake.claims++; return phase(CLAIM,(unsigned)w->kind);
}
static bool spi_cs(void *u,bool active) {
    (void)u;
    if(active) { CHECK(!fake.cs); fake.position=0; fake.address=0; fake.read_index=0; }
    else CHECK(fake.cs);
    fake.cs=active; return phase(active?CS_ON:CS_OFF,0);
}
static bool spi_byte(void *u,uint8_t tx,uint8_t *rx) {
    (void)u; CHECK(fake.cs); *rx=0;
    if(fake.position==0) {
        fake.opcode=tx; CHECK(fake.transaction_count<128); fake.opcodes[fake.transaction_count++]=tx;
        fake.address_bytes=(tx==0x13 || tx==0x0c)?4:(tx==3 || tx==0x0b || tx==0x90 || tx==0x5a)?3:0;
        fake.dummy_bytes=(tx==0xab)?3:(tx==0x0b || tx==0x0c || tx==0x5a)?1:0;
    } else if(fake.position<=fake.address_bytes) fake.address=(fake.address<<8)|tx;
    else if(fake.position>fake.address_bytes+fake.dummy_bytes) {
        unsigned index=fake.read_index++;
        if(fake.opcode==0x9f) { const uint8_t id[3]={0xef,0x40,0x19}; CHECK(index<3); *rx=id[index]; }
        else if(fake.opcode==5) *rx=0x1c;
        else if(fake.opcode==0x90) *rx=index?0x19:0xef;
        else if(fake.opcode==0xab) *rx=0x19;
        else if(fake.opcode==0x5a) *rx=(uint64_t)fake.address+index<sizeof(fake.sfdp)?fake.sfdp[fake.address+index]:0xff;
        else *rx=(uint8_t)(fake.address+index);
    }
    fake.position++; return phase(SPI_BYTE,tx);
}
static bool i2c_start(void *u,bool repeated) {
    (void)u;
    if(!repeated) { fake.i2c_writes=0; fake.i2c_address=0; fake.read_index=0; }
    return phase(repeated?RESTART:START,0);
}
static bool i2c_write(void *u,uint8_t value,bool *acked) {
    (void)u;
    if(fake.i2c_writes>0 && fake.i2c_writes<=wiring.bus.i2c.address_width)
        fake.i2c_address=(fake.i2c_address<<8)|value;
    fake.i2c_writes++; *acked=true;
    bool ok=phase(WRITE,value);
    if(fake.fault_phase==fake.phases && fake.effect==NACK) *acked=false;
    return ok;
}
static bool i2c_read(void *u,bool ack,uint8_t *value) {
    (void)u; *value=(uint8_t)(fake.i2c_address+fake.read_index++); return phase(ack?READ_ACK:READ_NACK,0);
}
static bool i2c_stop(void *u) { (void)u; return phase(STOP,0); }
static bool deliver(void *u,const probe_bus_chunk *chunk) {
    (void)u; CHECK(fake.deliveries<8); CHECK(chunk->length>0 && chunk->length<=256);
    for(unsigned i=0;i<chunk->length;i++) CHECK(chunk->bytes[i]==(uint8_t)(chunk->offset+i));
    fake.delivered[fake.deliveries++]=*chunk;
    return phase(DELIVER,chunk->length);
}
static void abort_bus(void *u,uint64_t mask,pweh_release_reason reason) {
    (void)u; CHECK(guarded.ctx.state==PROBE_BUS_STATE_RELEASED && guarded.ctx.credit==0);
    CHECK(guarded.ctx.claimed_mask==0 && !guarded.ctx.spi_info.sfdp_valid);
    CHECK(reason!=PWEH_RELEASE_NONE); fake.aborts++; fake.abort_mask=mask; fake.cs=false;
    CHECK(fake.used<4096); fake.events[fake.used++]=(event){ABORT,(unsigned)reason};
}
static probe_bus_hal hal(void) {
    probe_bus_hal h={.clock_ms=clock_ms,.read_vref=read_vref,.claim=claim,.spi_cs=spi_cs,
        .spi_byte=spi_byte,.i2c_start=i2c_start,.i2c_write_byte=i2c_write,.i2c_read_byte=i2c_read,
        .i2c_stop=i2c_stop,.deliver_chunk=deliver,.abort=abort_bus}; return h;
}
static bool emit(void *u,const uint8_t *data,size_t size) {
    (void)u; CHECK(size<=sizeof(fake.wire)); memcpy(fake.wire,data,size); fake.wire_size=size; return true;
}
static void common_release(void *u,pweh_release_reason reason) { (void)u; (void)reason; }
static pweh_frame exchange(pweh_frame *frame) {
    uint8_t wire[PWEH_MAX_WIRE];size_t n=0; pweh_frame response;
    CHECK(pweh_frame_encode(frame,wire,sizeof(wire),&n)==PWEH_OK);
    CHECK(pweh_probe_feed(&common.probe,wire,n,100)==PWEH_OK);
    CHECK(pweh_frame_decode(fake.wire,fake.wire_size,&response)==PWEH_OK); return response;
}
static void common_hello(void) {
    pweh_identity id={.fw_name="PWEH espprobe",.fw_version="0.1.0",.profile="probe-hello",
        .board="esp32s3-devkitc1-hello",.git_commit="0000000000000000000000000000000000000000",
        .idf_version="simulator",.usb_product="PWEH espprobe",.base_mac={2,0,0,0,0,1},
        .vid=12346,.pid=16386,.reset_reason=1,.hb_ms=1000,.chip_model=1,.chip_known=3};
    static uint8_t policy[73]={19,0,4,0,0,0,0,0,20,0,6,0,0,16,232,3,0,0,21,0,24,0};
    const uint8_t tail[]={22,0,1,0,255,23,0,1,0,0,24,0,0,0,25,0,1,0,0,26,0,4,0,0,0,0,0};
    memcpy(policy+46,tail,sizeof(tail)); id.policy=policy; id.policy_size=sizeof(policy);
    memset(id.boot_id,7,sizeof(id.boot_id)); memset(id.image_sha256,17,32); memset(id.app_elf_sha256,34,32);
    pweh_hal h={.emit=emit,.release=common_release}; CHECK(pweh_probe_init(&common.probe,&id,&h));
    pweh_frame hello={.version=1,.type=1,.op=1,.seq=1,.length=20};
    hello.payload[0]=1; hello.payload[2]=16; for(unsigned i=0;i<16;i++) hello.payload[i+4]=(uint8_t)i;
    pweh_frame response=exchange(&hello);
    CHECK(response.session>0 && response.flags==0 && pweh_get16(response.payload)==0);
    CHECK(!memcmp(response.payload+6,hello.payload+4,16));
    binding=(probe_bus_binding){.session=common.probe.session,.usb_session=common.probe.usb_session,
        .hello_seq=common.probe.hello_seq,.last_hb_seq=common.probe.last_hb_seq,.hb_ms=id.hb_ms,
        .now_ms=common.probe.now_ms,.deadline_ms=common.probe.deadline_ms};
    memcpy(binding.boot_id,common.probe.identity.boot_id,16);
}
static void sfdp_image(unsigned variant) {
    memset(fake.sfdp,0,sizeof(fake.sfdp)); memcpy(fake.sfdp,"SFDP",4);
    fake.sfdp[4]=6; fake.sfdp[5]=1; fake.sfdp[6]=1; fake.sfdp[7]=0xff;
    const uint8_t bfpt[]={0,6,1,9,0x40,0,0,0xff}, bait[]={0x84,1,1,2,0x80,0,0,0xff};
    memcpy(fake.sfdp+8,bfpt,8); memcpy(fake.sfdp+16,bait,8);
    pweh_put32(fake.sfdp+0x40,UINT32_C(1)<<17);
    pweh_put32(fake.sfdp+0x44,0x0fffffffu); pweh_put32(fake.sfdp+0x80,3);
    switch(variant) {
    case 1: pweh_put32(fake.sfdp+0x44,0x03ffffffu); break; /* 8 MiB */
    case 2: fake.sfdp[6]=0; break; /* 큰 용량, 4BAIT 없음 */
    case 3: pweh_put32(fake.sfdp+0x80,1); break;
    case 4: pweh_put32(fake.sfdp+0x80,2); break;
    case 5: pweh_put32(fake.sfdp+0x44,0x80000023u); break; /* 4 GiB */
    case 6: pweh_put32(fake.sfdp+0x44,0x07ffffffu); break; /* 정확한 24bit 주소 끝 */
    case 10: fake.sfdp[0]='X'; break;
    case 11: fake.sfdp[5]=2; break;
    case 12: fake.sfdp[6]=16; break;
    case 13: fake.sfdp[11]=8; break;
    case 14: fake.sfdp[19]=1; break;
    case 15: fake.sfdp[10]=2; break;
    case 16: memcpy(fake.sfdp+16,bfpt,8); break;
    case 17: fake.sfdp[12]=0xfcu;fake.sfdp[13]=0xff;fake.sfdp[14]=0xff; break;
    case 18: fake.sfdp[12]=0x41; break;
    case 19: fake.sfdp[12]=8; break;
    case 20: fake.sfdp[20]=0x60; break;
    case 21: pweh_put32(fake.sfdp+0x40,UINT32_C(3)<<17); break;
    case 22: pweh_put32(fake.sfdp+0x44,8); break;
    case 23: pweh_put32(fake.sfdp+0x44,0x80000024u); break;
    case 24: fake.sfdp[7]=0; break;
    case 25: pweh_put32(fake.sfdp+0x44,0x80000002u); break;
    case 26: pweh_put32(fake.sfdp+0x40,UINT32_C(2)<<17);pweh_put32(fake.sfdp+0x44,0x03ffffffu);break;
    default: break;
    }
}
static void reset_trace(void) {
    fake.used=fake.phases=fake.clocks=fake.vrefs=fake.aborts=fake.deliveries=fake.claims=0;
    fake.after_abort=fake.nested_checks=fake.transaction_count=0;
    fake.fault_phase=fake.fault_clock=fake.fault_vref=0;
}
static void base(unsigned kind,unsigned width) {
    memset(&fake,0,sizeof(fake)); fake.now=100;fake.mv=3300;
    guarded.before=guarded.after=common.before=common.after=output.before=output.after=CANARY;
    common_hello(); sfdp_image(0);
    wiring=(probe_bus_wiring){.kind=kind?PROBE_I2C_EEPROM_READ:PROBE_SPI_READ_RANGE,
        .declared_mv=3300,.allowed_mask=15};
    if(kind) wiring.bus.i2c=(probe_i2c_wiring){.scl=0,.sda=1,.addr7=0x50,.address_width=(uint8_t)width,.capacity=width==1?256:65536};
    else wiring.bus.spi=(probe_spi_pins){.cs=0,.sck=1,.mosi=2,.miso=3};
    probe_bus_hal h=hal();CHECK(probe_bus_init(&guarded.ctx,&h)==PROBE_BUS_OK);
    CHECK(probe_bus_bind(&guarded.ctx,&binding)==PROBE_BUS_OK);
}
static probe_spi_info ready(unsigned kind,unsigned width,unsigned variant) {
    base(kind,width);sfdp_image(variant);
    CHECK(probe_bus_claim(&guarded.ctx,&wiring,fake.now)==PROBE_BUS_OK);
    probe_spi_info info={0};
    if(!kind) CHECK(probe_spi_probe(&guarded.ctx,2,fake.now,&info)==PROBE_BUS_OK);
    reset_trace();return info;
}
static void begin(unsigned kind,unsigned passes,unsigned length,uint32_t offset) {
    plan=(probe_read_plan){.kind=kind?PROBE_I2C_EEPROM_READ:PROBE_SPI_READ_RANGE,.passes=(uint8_t)passes,.offset=offset,.length=length};
    CHECK(probe_bus_begin(&guarded.ctx,3,&plan,fake.now)==PROBE_BUS_OK);
}
static void grant(unsigned seq,unsigned credit) {
    CHECK(probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,seq,(uint16_t)credit,fake.now)==PROBE_BUS_OK);
}
static void report(probe_bus_result result) {
    canaries(); CHECK(fake.used<4096 && fake.after_abort==0);
    printf("{\"result\":%u,\"state\":%u,\"reason\":%u,\"phases\":%u,\"clocks\":%u,\"vrefs\":%u,\"aborts\":%u,\"mask\":%llu,\"deliveries\":%u,\"claims\":%u,\"credit\":%u,\"nested\":%u,\"out_zero\":%s,\"trace\":[",
        result,guarded.ctx.state,guarded.ctx.last_release_reason,fake.phases,fake.clocks,fake.vrefs,fake.aborts,
        (unsigned long long)fake.abort_mask,fake.deliveries,fake.claims,guarded.ctx.credit,fake.nested_checks,
        zero(&output.chunk,sizeof(output.chunk))?"true":"false");
    for(unsigned i=0;i<fake.used;i++) printf("%s[%u,%u]",i?",":"",fake.events[i].code,fake.events[i].value);
    printf("],\"chunks\":[");
    for(unsigned i=0;i<fake.deliveries;i++) {probe_bus_chunk *c=&fake.delivered[i];
        printf("%s[%u,%u,%u,%s]",i?",":"",c->pass_index,c->offset,c->length,c->done?"true":"false");}
    printf("]}\n");
}
static unsigned arg(char **argv,int argc,int i,unsigned fallback) {
    if(i>=argc)return fallback; char *end=NULL;unsigned long n=strtoul(argv[i],&end,10);
    CHECK(*argv[i] && end && !*end && n<=UINT32_MAX);return (unsigned)n;
}
int main(int argc,char **argv) {
    if(argc<2||argc>8)return 2;
    unsigned a=arg(argv,argc,2,0),b=arg(argv,argc,3,0),c=arg(argv,argc,4,0),d=arg(argv,argc,5,0);
    probe_bus_result result=PROBE_BUS_OK;
    if(!strcmp(argv[1],"hello")) {
        base(0,0);CHECK(guarded.ctx.binding.session==common.probe.session);
        pweh_frame req={.version=1,.type=1,.op=60,.seq=2,.session=common.probe.session};
        pweh_frame rsp=exchange(&req);CHECK(pweh_get16(rsp.payload)==2);
        req.type=5;req.op=0;req.seq=1;req.credit=1;rsp=exchange(&req);CHECK(pweh_get16(rsp.payload)==1);
        CHECK(common.probe.last_hb_seq==0 && fake.phases==0);
    } else if(!strcmp(argv[1],"init")) {
        base(0,0);probe_bus_hal h=hal();
        switch(a) {case 0:h.clock_ms=NULL;break;case 1:h.read_vref=NULL;break;case 2:h.claim=NULL;break;
        case 3:h.spi_cs=NULL;break;case 4:h.spi_byte=NULL;break;case 5:h.i2c_start=NULL;break;
        case 6:h.i2c_write_byte=NULL;break;case 7:h.i2c_read_byte=NULL;break;case 8:h.i2c_stop=NULL;break;
        case 9:h.deliver_chunk=NULL;break;case 10:h.abort=NULL;break;default:return 2;}
        result=probe_bus_init(&guarded.ctx,&h);CHECK(fake.phases==0);
    } else if(!strcmp(argv[1],"claim")) {
        base(a,2);
        switch(b) {case 0:wiring.declared_mv=0;break;case 1:wiring.declared_mv=2999;break;
        case 2:wiring.declared_mv=3601;break;case 3:wiring.allowed_mask=0;break;case 4:wiring.excluded_mask=1;break;
        case 5:if(a)wiring.bus.i2c.sda=0;else wiring.bus.spi.miso=0;break;
        case 6:if(a)wiring.bus.i2c.sda=64;else wiring.bus.spi.miso=64;break;
        case 7:fake.mv=2999;break;case 8:fake.mv=3601;break;case 9:fake.invalid_vref=true;break;
        case 10:fake.stale_vref=true;break;case 11:fake.future_vref=true;break;
        case 12:wiring.declared_mv=3600;fake.mv=3000;break;
        case 13:fake.fault_phase=1;fake.effect=FAIL;break;
        case 14:wiring.bus.i2c.addr7=7;break;case 15:wiring.bus.i2c.addr7=0x78;break;
        case 16:wiring.bus.i2c.address_width=0;break;case 17:wiring.bus.i2c.address_width=3;break;
        case 18:wiring.bus.i2c.capacity=65537;break;case 19:wiring.bus.i2c.capacity=0;break;
        default:return 2;}
        result=probe_bus_claim(&guarded.ctx,&wiring,fake.now);
    } else if(!strcmp(argv[1],"sfdp")) {
        base(0,0);sfdp_image(a);CHECK(probe_bus_claim(&guarded.ctx,&wiring,fake.now)==PROBE_BUS_OK);
        if(b) {CHECK(b<=136 && c<=255);fake.sfdp[b-1]^=(uint8_t)c;}
        reset_trace();probe_spi_info info;memset(&info,0xa5,sizeof(info));
        result=probe_spi_probe(&guarded.ctx,2,fake.now,&info);
        CHECK(fake.transaction_count>=3 && fake.opcodes[0]==0x9f && fake.opcodes[1]==5);
        for(unsigned i=2;i<fake.transaction_count;i++)CHECK(fake.opcodes[i]==0x5a);
        CHECK(guarded.ctx.sfdp_read_bytes<=4096);
        printf("{\"result\":%u,\"valid\":%s,\"capacity\":%llu,\"read4\":%s,\"fast4\":%s,\"bytes\":%u,\"transactions\":%u}\n",
            result,info.sfdp_valid?"true":"false",(unsigned long long)info.capacity,
            info.read4_supported?"true":"false",info.fast4_supported?"true":"false",guarded.ctx.sfdp_read_bytes,fake.transaction_count);
        canaries();return 0;
    } else if(!strcmp(argv[1],"spi")) {
        (void)ready(0,0,b);uint8_t bytes[256]={0};uint16_t length=a==0x9f?3:a==0x90?2:1;
        uint32_t address=(a==3||a==0x0b)?0x123456u:(a==0x13||a==0x0c)?0x1000000u:0;
        if(c==1)length=0; if(c==2)length=257;if(c==3)address=UINT32_MAX;
        if(c==4){address=0xffffff;length=2;}
        if(c==5){address=0xffffff;length=1;}
        result=probe_spi_xfer(&guarded.ctx,(uint8_t)a,address,length,bytes);
    } else if(!strcmp(argv[1],"descriptor")) {
        (void)ready(0,0,1);
        probe_spi_descriptor desc={.opcode=3,.first_byte=3,.address_bytes=3,.address=0,.length=1};
        switch(a) {case 0:desc.first_byte=6;break;case 1:desc.address_bytes=4;break;
        case 2:desc.dummy_bytes=1;break;case 3:desc.length=0;break;case 4:desc.length=257;break;
        case 5:desc.address=0x800000;break;case 6:desc.opcode=desc.first_byte=6;break;
        case 7:desc.opcode=desc.first_byte=0x5a;desc.dummy_bytes=1;break;
        case 8: /* 내부 parser의 누적 예산이 이미 소진된 부정 입력이다. */
            desc.opcode=desc.first_byte=0x5a;desc.dummy_bytes=1;
            guarded.ctx.sfdp_active=true;guarded.ctx.sfdp_read_bytes=4096;break;
        case 9:desc.opcode=desc.first_byte=0x5a;desc.dummy_bytes=1;
            guarded.ctx.sfdp_active=true;desc.address=0xffffff;desc.length=2;break;
        default:return 2;}
        result=probe_spi_validate(&guarded.ctx,&desc);CHECK(fake.phases==0);
    } else if(!strcmp(argv[1],"read")) {
        (void)ready(a,b,arg(argv,argc,7,0));unsigned length=d?d:(a?33:257);uint32_t offset=arg(argv,argc,6,a?(b==1?17:0x1234):0x1000000);
        unsigned passes=c?c:2;begin(a,passes,length,offset);
        unsigned chunk=a?32:256;unsigned count=((length+chunk-1)/chunk)*passes;CHECK(count<=8);
        unsigned hb=1;
        for(unsigned i=0;i<count;i++) { if(guarded.ctx.credit==0)grant(hb++,count-i>4?4:count-i);
            memset(&output.chunk,0xa5,sizeof(output.chunk));result=probe_bus_step(&guarded.ctx,fake.now,&output.chunk);
            CHECK(result==PROBE_BUS_OK && !memcmp(&output.chunk,&fake.delivered[i],sizeof(output.chunk)));}
        CHECK(guarded.ctx.state==PROBE_BUS_STATE_DONE);
        unsigned old=fake.phases;memset(&output.chunk,0xa5,sizeof(output.chunk));
        CHECK(probe_bus_step(&guarded.ctx,fake.now,&output.chunk)==PROBE_BUS_DONE && fake.phases==old);
    } else if(!strcmp(argv[1],"fault") || !strcmp(argv[1],"observe")) {
        (void)ready(a,2,0);begin(a,1,3,a?0x1234:0x1000000);grant(1,1);reset_trace();
        fake.effect=c;
        if(!strcmp(argv[1],"fault")) fake.fault_phase=b;
        else if(d)fake.fault_vref=b;else fake.fault_clock=b;
        memset(&output.chunk,0xa5,sizeof(output.chunk));result=probe_bus_step(&guarded.ctx,fake.now,&output.chunk);
        if(guarded.ctx.state==PROBE_BUS_STATE_RELEASED) {
            CHECK(zero(&output.chunk,sizeof(output.chunk)));unsigned old=fake.phases;
            CHECK(probe_bus_step(&guarded.ctx,fake.now,&output.chunk)==PROBE_BUS_RELEASED);
            (void)probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,2,1,fake.now);
            (void)probe_bus_begin(&guarded.ctx,4,&plan,fake.now);
            probe_bus_release(&guarded.ctx,PWEH_RELEASE_HOST);CHECK(fake.phases==old && fake.aborts==1);
        }
    } else if(!strcmp(argv[1],"range")) {
        (void)ready(a,2,b==8?5:0);plan=(probe_read_plan){.kind=a?PROBE_I2C_EEPROM_READ:PROBE_SPI_READ_RANGE,.passes=1,.length=1};
        switch(b) {case 0:plan.length=0;break;case 1:plan.passes=0;break;case 2:plan.passes=3;break;
        case 3:plan.device_index=1;break;case 4:plan.kind=a?PROBE_SPI_READ_RANGE:PROBE_I2C_EEPROM_READ;break;
        case 5:plan.offset=a?65536:0x2000000;break;case 6:plan.offset=UINT32_MAX;plan.length=2;break;
        case 7:plan.offset=a?65535:0x1ffffff;plan.length=2;break;case 8:plan.offset=UINT32_MAX;plan.length=1;break;default:return 2;}
        result=probe_bus_begin(&guarded.ctx,3,&plan,fake.now);
    } else if(!strcmp(argv[1],"delivery")) {
        (void)ready(a,2,0);begin(a,2,a?33:257,a?0x1234:0x1000000);grant(1,4);
        CHECK(b>=1 && b<=4);unsigned before=0;
        for(unsigned i=1;i<=b;i++) {
            if(i==b) {fake.fault_phase=fake.phases+(i%2?(a?40:264):9);fake.effect=c;}
            before=fake.deliveries;
            result=probe_bus_step(&guarded.ctx,fake.now,&output.chunk);
            if(i<b)CHECK(result==PROBE_BUS_OK);
        }
        CHECK(fake.deliveries==before+1 && fake.deliveries==b);
        CHECK(guarded.ctx.state==PROBE_BUS_STATE_RELEASED && zero(&output.chunk,sizeof(output.chunk)));
        unsigned old=fake.phases;CHECK(probe_bus_step(&guarded.ctx,fake.now,&output.chunk)==PROBE_BUS_RELEASED);
        (void)probe_bus_begin(&guarded.ctx,3,&plan,fake.now);
        (void)probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,2,1,fake.now);
        CHECK(fake.phases==old);
    } else if(!strcmp(argv[1],"binding")) {
        base(0,0);probe_bus_release(&guarded.ctx,PWEH_RELEASE_REQUEST);binding.session++;
        switch(a) {case 0:binding.session=0;break;case 1:binding.usb_session=0;break;
        case 2:binding.hello_seq=0;break;case 3:binding.hb_ms=249;break;case 4:binding.hb_ms=3001;break;
        case 5:binding.deadline_ms=binding.now_ms;break;case 6:binding.deadline_ms=binding.now_ms+1001;break;
        case 7:binding.now_ms--;break;case 8:binding.session--;break;
        default:return 2;}
        result=probe_bus_bind(&guarded.ctx,&binding);CHECK(fake.phases==0);
    } else if(!strcmp(argv[1],"poll")) {
        (void)ready(a,2,0);fake.effect=b;(void)effect(b);
        result=probe_bus_poll(&guarded.ctx,fake.now);
        CHECK(guarded.ctx.state==PROBE_BUS_STATE_RELEASED && fake.phases==0);
    } else if(!strcmp(argv[1],"lifecycle")) {
        probe_spi_info info=ready(0,0,0);begin(0,2,257,0x1000000);
        if(a==0) {
            memset(&output.chunk,0xa5,sizeof(output.chunk));CHECK(probe_bus_step(&guarded.ctx,fake.now,&output.chunk)==PROBE_BUS_NO_CREDIT);
            CHECK(zero(&output.chunk,sizeof(output.chunk)) && fake.phases==0);
            grant(1,4);uint64_t end=guarded.ctx.deadline_ms;fake.now++;
            CHECK(probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,1,4,fake.now)==PROBE_BUS_OK);
            CHECK(guarded.ctx.credit==4 && guarded.ctx.deadline_ms==end);
            CHECK(probe_bus_credit(&guarded.ctx,binding.session+1,binding.usb_session,2,0,fake.now)==PROBE_BUS_SESSION);
            CHECK(probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session+1,2,0,fake.now)==PROBE_BUS_SESSION);
            CHECK(probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,2,1,fake.now)!=PROBE_BUS_OK);
            CHECK(fake.phases==0);
        } else if(a==1) {
            CHECK(probe_bus_begin(&guarded.ctx,3,&plan,fake.now)==PROBE_BUS_OK);
            probe_read_plan other=plan;other.length++;
            CHECK(probe_bus_begin(&guarded.ctx,3,&other,fake.now)==PROBE_BUS_SEQUENCE);
            CHECK(probe_spi_probe(&guarded.ctx,3,fake.now,&info)==PROBE_BUS_SEQUENCE);
            CHECK(probe_bus_begin(&guarded.ctx,4,&plan,fake.now)==PROBE_BUS_BUSY);
            CHECK(fake.phases==0);
        } else if(a==2) {
            grant(1,4);for(unsigned i=0;i<4;i++)CHECK(probe_bus_step(&guarded.ctx,fake.now,&output.chunk)==PROBE_BUS_OK);
            unsigned old=fake.phases;CHECK(probe_bus_begin(&guarded.ctx,3,&plan,fake.now)==PROBE_BUS_OK);
            CHECK(probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,2,1,fake.now)!=PROBE_BUS_OK);
            grant(2,0);CHECK(fake.phases==old && guarded.ctx.state==PROBE_BUS_STATE_DONE);
        } else if(a==3) {
            fake.now=guarded.ctx.deadline_ms;
            result=probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,1,1,fake.now);
            CHECK(guarded.ctx.state==PROBE_BUS_STATE_RELEASED && fake.phases==0);
        } else if(a==4) {
            probe_bus_release(&guarded.ctx,PWEH_RELEASE_USB_RESET);
            CHECK(probe_bus_bind(&guarded.ctx,&binding)==PROBE_BUS_SESSION);
            binding.session++;CHECK(probe_bus_bind(&guarded.ctx,&binding)==PROBE_BUS_OK);
            CHECK(guarded.ctx.state==PROBE_BUS_STATE_BOUND && !guarded.ctx.spi_info.sfdp_valid);
            CHECK(probe_bus_begin(&guarded.ctx,4,&plan,fake.now)!=PROBE_BUS_OK);
        } else if(a==5) {
            grant(UINT32_MAX,1);uint16_t credit=guarded.ctx.credit;uint64_t end=guarded.ctx.deadline_ms;
            (void)probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,0,1,fake.now);
            CHECK(guarded.ctx.credit==credit && guarded.ctx.deadline_ms==end);
        } else if(a==6) {
            probe_bus_release(&guarded.ctx,PWEH_RELEASE_REQUEST);binding.session++;binding.usb_session=0;
            CHECK(probe_bus_bind(&guarded.ctx,&binding)!=PROBE_BUS_OK);
        } else if(a==7) {
            probe_bus_release(&guarded.ctx,PWEH_RELEASE_REQUEST);binding.session++;binding.now_ms=UINT64_MAX-10;binding.deadline_ms=UINT64_MAX;
            fake.now=binding.now_ms;CHECK(probe_bus_bind(&guarded.ctx,&binding)==PROBE_BUS_OK);
            result=probe_bus_credit(&guarded.ctx,binding.session,binding.usb_session,1,0,fake.now);
            CHECK(guarded.ctx.state==PROBE_BUS_STATE_RELEASED);
        } else if(a==8) {
            info.sfdp_valid=false;info.capacity=1;info.read4_supported=false;
            grant(1,1);CHECK(probe_bus_step(&guarded.ctx,fake.now,&output.chunk)==PROBE_BUS_OK);
            CHECK(fake.opcodes[0]==0x13);
        } else return 2;
    } else if(!strcmp(argv[1],"cache")) {
        base(0,0);CHECK(probe_bus_claim(&guarded.ctx,&wiring,fake.now)==PROBE_BUS_OK);
        probe_spi_info info;
        for(unsigned seq=2;seq<7;seq++) { CHECK(probe_spi_probe(&guarded.ctx,seq,fake.now,&info)==PROBE_BUS_OK); reset_trace(); }
        CHECK(probe_spi_probe(&guarded.ctx,6,fake.now,&info)==PROBE_BUS_OK);
        CHECK(probe_spi_probe(&guarded.ctx,2,fake.now,&info)==PROBE_BUS_REPLAY);
        CHECK(fake.phases==0);
    } else return 2;
    report(result);return 0;
}
