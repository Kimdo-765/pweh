/* 합성 입력만 쓰는 host 시험. Windows 헤더·포트·PnP는 링크하지 않는다. */
#define PWEH_HOST_TEST
#include "pweh-serial-helper.c"
#undef NDEBUG
#include <assert.h>
#include <stdio.h>

static unsigned frames;
static uint8_t seen_type, seen_payload[MAX_PAYLOAD];
static unsigned seen_length;
static int sink(void *ctx, uint8_t type, const uint8_t *data, unsigned size) {
    (void)ctx; ++frames; seen_type = type; seen_length = size;
    memcpy(seen_payload, data, size); return 1;
}
static void parser_tests(void) {
    const uint8_t golden[] = {'O',14,0, 1,0,0,0, 0,194,1,0, 8,0,0,0,0,0};
    for (unsigned split = 0; split <= sizeof(golden); ++split) {
        Parser parser = {0}; frames = 0;
        assert(feed(&parser, golden, split, 10, sink, NULL) == 0);
        assert(feed(&parser, golden + split, sizeof(golden) - split, 20, sink, NULL) == 0);
        assert(frames == 1 && seen_type == 'O' && seen_length == 14 && u32(seen_payload + 4) == 115200);
        assert(parser.used == 0);
    }
    Parser bytewise = {0}; frames = 0;
    for (unsigned i = 0; i < sizeof(golden); ++i) assert(feed(&bytewise, golden + i, 1, i + 1, sink, NULL) == 0);
    assert(frames == 1);
    for (unsigned prefix = 1; prefix < sizeof(golden); ++prefix) {
        Parser parser = {0}; frames = 0;
        assert(feed(&parser, golden, prefix, 10, sink, NULL) == 0);
        assert(parser.used == prefix && parser.started == 10 && frames == 0);
    }
    const uint8_t bad_heads[][3] = {{'D',1,64},{'D',255,255},{'D',0,0},{'D',3,0}};
    for (unsigned i = 0; i < 4; ++i) {
        Parser parser = {0}; assert(feed(&parser, bad_heads[i], 3, 1, sink, NULL) == -1);
    }
    static uint8_t maximum[MAX_FRAME];
    maximum[0] = 'D'; maximum[1] = 0; maximum[2] = 64; put32(maximum + 3, 1); put32(maximum + 7, 30000);
    Parser parser = {0}; frames = 0;
    assert(feed(&parser, maximum, sizeof(maximum), 1, sink, NULL) == 0);
    assert(frames == 1 && seen_length == MAX_PAYLOAD);
    for (unsigned i = 0; i < 256; ++i) {
        if (i == 'O' || i == 'B' || i == 'L' || i == 'K' || i == 'P' || i == 'S' || i == 'D' || i == 'Q') continue;
        assert(!valid_request((uint8_t)i, golden + 3, 14));
    }
    uint8_t command[14]; memcpy(command, golden + 3, 14);
    command[13] = 1; assert(!valid_request('O', command, 14)); command[13] = 0;
    command[11] = 2; assert(!valid_request('O', command, 14)); command[11] = 0;
    command[8] = 4; assert(!valid_request('O', command, 14)); command[8] = 8;
    put32(command, 0); assert(!valid_request('O', command, 14));
    uint8_t d[9] = {1,0,0,0,1,0,0,0,0};
    assert(valid_request('D', d, 9)); put32(d + 4, 0); assert(!valid_request('D', d, 9));
    put32(d + 4, 30001); assert(!valid_request('D', d, 9));
    uint8_t p[9] = {1,0,0,0,2,1,0,0,0}; assert(valid_request('P', p, 9));
    p[4] = 3; assert(!valid_request('P', p, 9)); p[4] = 0; put32(p + 5, 5001); assert(!valid_request('P', p, 9));
    uint8_t k[9] = {1,0,0,0,2,1,0,0,0}; assert(valid_request('K', k, 9));
    k[4] = 1; assert(!valid_request('K', k, 9)); put32(k + 5, 0); assert(valid_request('K', k, 9));
    uint8_t l[6] = {1,0,0,0,255,0}; assert(valid_request('L', l, 6));
    l[5] = 255; assert(!valid_request('L', l, 6));
}
static void com_tests(void) {
    const char *samples[] = {"COM1", "COM9", "COM10", "COM4096", "COM0", "COM4097", "COM01", "com1", "COM1:", "COM-1", "COM1/x", "\\\\.\\PhysicalDrive0", "\\\\.\\pipe\\x", "COM"};
    for (unsigned i = 0; i < sizeof(samples) / sizeof(samples[0]); ++i) {
        uint16_t text[64] = {0}; unsigned n = 0;
        while (samples[i][n]) { text[n] = (unsigned char)samples[i][n]; ++n; }
        assert((com_number(text) != 0) == (i < 4));
    }
    uint16_t token[40] = {0}; for (unsigned i = 0; i < 32; ++i) token[i] = 'a';
    assert(valid_token(token)); token[32] = 'b'; assert(!valid_token(token)); token[32] = 0;
    token[3] = 'A'; assert(!valid_token(token)); token[3] = 0; assert(!valid_token(token));
    const uint16_t option[] = {'-','-','p','o','r','t',0}; assert(eq16(option, "--port")); assert(!eq16(option, "--echo"));
}
typedef struct { uint64_t time; unsigned cancels, polls, complete_at; } FakeIo;
static void fake_cancel(void *v) { ((FakeIo *)v)->cancels++; }
static int fake_poll(void *v) { FakeIo *f = v; return ++f->polls >= f->complete_at; }
static uint64_t fake_clock(void *v) { return ((FakeIo *)v)->time; }
static void fake_pause(void *v) { ((FakeIo *)v)->time += 5; }
static void cancel_tests(void) {
    FakeIo fake = {0,0,0,4}; CancelOps ops = {&fake, fake_cancel, fake_poll, fake_clock, fake_pause};
    assert(cancel_complete(&ops, 50)); assert(fake.cancels == 1 && fake.polls == 4 && fake.time == 15);
    fake = (FakeIo){0,0,0,1000};
    assert(!cancel_complete(&ops, 20)); assert(fake.cancels == 1 && fake.time == 20 && fake.polls == 5);
    fake = (FakeIo){0,0,0,1}; assert(cancel_complete(&ops, 20)); assert(fake.time == 0);
}
int main(void) { parser_tests(); com_tests(); cancel_tests(); puts("native parser/com/cancel: ok"); return 0; }
