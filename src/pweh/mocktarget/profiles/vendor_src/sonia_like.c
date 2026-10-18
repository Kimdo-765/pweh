/*
 * sonia_like.c - PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE
 *
 * pweh.mocktarget 'dahua-like' 프로필의 합성 메인 서비스 (/usr/bin/sonia).
 * 이름(/usr/bin/sonia), 설정 경로(/mnt/mtd/Config/, Account1), JSON-RPC 로그인 어휘(/RPC2_Login, /RPC2,
 * global.login, clientType / loginType / ipAddr), /current_config/ 매핑은 docs/references/cctv-vuln-patterns.md
 * §3.2·§4.2 에 공개된 "펌웨어 쪽 지표"만 빌렸다. 코드는 처음부터 새로 쓴 합성 코드이며 실제 벤더 코드·키·
 * 자격증명·요청 형식을 담지 않는다. 시뮬레이터는 이 바이너리를 실행하지 않는다 (정적 분석 대상).
 *
 * 분석 파이프라인 정답(ground truth) 검증용으로 "의도적으로" 심은 취약점 클래스
 * (같은 id 가 펌웨어 매니페스트 planted_issues 에 있다):
 *   PWEH-DH-01  로그인 처리가 "로컬 요청" 여부를 소켓 peer 주소가 아니라 클라이언트가 요청 본문에 써 넣은
 *               loginType / ipAddr 값으로 판정하고, 로컬이면 비밀번호 검증을 건너뛴다.
 *               peer 주소(getpeername)는 계산하지만 판정에 쓰지 않는다 (패턴 P4, CVE-2021-33045 계열).
 *   PWEH-DH-02  /current_config/ 접두사 요청을 세션 확인보다 먼저 /mnt/mtd/Config/ 의 파일로 매핑해 내려준다.
 *               같은 디렉터리에 계정 DB(Account1)가 있다 (패턴 P1/P8, CVE-2017-7925 계열).
 *               파일 이름의 '/' 와 ".." 는 거부하므로 경로 순회는 아니다.
 * 비밀번호는 런타임 계정 DB 에서만 읽는다 (바이너리에 고정 자격증명 없음).
 *
 * 빌드: zig cc -target arm-linux-musleabi -static -O2 -fno-inline -o sonia sonia_like.c
 */
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PWEH_MARKER "PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE"
#define SERVER_NAME "sonia-synthetic/1.0"
#define DEFAULT_PORT 8080
#define CONFIG_DIR "/mnt/mtd/Config/"
#define ACCOUNT_DB "/mnt/mtd/Config/Account1"
#define CONFIG_URI_PREFIX "/current_config/"
#define RPC_LOGIN_PATH "/RPC2_Login"
#define RPC_PATH "/RPC2"
#define MAX_REQ 4096
#define MAX_SESSIONS 16

const char pweh_marker[] = PWEH_MARKER;

struct http_req {
    char method[8];
    char path[256];
    char cookie[128];
    char body[1536];
};

struct login_req {
    char user[64];
    char pass[96];
    char client_type[32];
    char login_type[32];
    char ip_addr[48];
};

static char g_sessions[MAX_SESSIONS][33];

static void send_text(int fd, int code, const char *status, const char *ctype, const char *body)
{
    char hdr[384];
    int n = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %u\r\n\r\n",
                     code, status, SERVER_NAME, ctype, (unsigned)strlen(body));
    if (n > 0 && write(fd, hdr, (size_t)n) < 0)
        return;
    if (write(fd, body, strlen(body)) < 0)
        return;
}

/* 요청 본문(JSON)에서 "key" : "value" 를 꺼낸다 (합성: 아주 단순한 파서) */
static int json_get(const char *body, const char *key, char *out, size_t outlen)
{
    char pat[48];
    const char *p, *e;
    size_t n;
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    p = strstr(body, pat);
    if (!p)
        return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p)
        return 0;
    p = strchr(p, '"');
    if (!p)
        return 0;
    p++;
    e = strchr(p, '"');
    if (!e)
        return 0;
    n = (size_t)(e - p);
    if (n + 1 > outlen)
        n = outlen - 1;
    memcpy(out, p, n);
    out[n] = '\0';
    return 1;
}

/* 비밀번호 비교용 합성 다이제스트 (FNV-1a 64) — 저장 값은 런타임 계정 DB 에만 있다 */
static unsigned long long pw_digest(const char *user, const char *pass)
{
    unsigned long long h = 1469598103934665603ULL;
    const char *s;
    for (s = user; *s; s++)
        h = (h ^ (unsigned char)*s) * 1099511628211ULL;
    h = (h ^ ':') * 1099511628211ULL;
    for (s = pass; *s; s++)
        h = (h ^ (unsigned char)*s) * 1099511628211ULL;
    return h;
}

static int verify_password(const char *user, const char *pass)
{
    char line[256];
    int ok = 0;
    FILE *f = fopen(ACCOUNT_DB, "r");
    if (!f)
        return 0;
    while (fgets(line, sizeof(line), f)) {
        char name[64];
        unsigned long long stored = 0;
        if (sscanf(line, "%63[^:]:%llx", name, &stored) == 2 && strcmp(name, user) == 0) {
            ok = (stored == pw_digest(user, pass));
            break;
        }
    }
    fclose(f);
    return ok;
}

static void new_session_id(char out[33])
{
    unsigned char rnd[16];
    int i, fd = open("/dev/urandom", O_RDONLY);
    memset(rnd, 0, sizeof(rnd));
    if (fd >= 0) {
        if (read(fd, rnd, sizeof(rnd)) != (ssize_t)sizeof(rnd))
            memset(rnd, 0, sizeof(rnd));
        close(fd);
    }
    for (i = 0; i < 16; i++)
        snprintf(out + i * 2, 3, "%02x", rnd[i]);
}

static int session_valid(const struct http_req *r)
{
    int i;
    const char *sid = strstr(r->cookie, "SessionID=");
    if (!sid)
        return 0;
    sid += 10;
    for (i = 0; i < MAX_SESSIONS; i++) {
        if (g_sessions[i][0] && strncmp(g_sessions[i], sid, 32) == 0)
            return 1;
    }
    return 0;
}

static void send_login_result(int fd, int ok, const char *user)
{
    char body[256];
    if (ok) {
        int i;
        for (i = 0; i < MAX_SESSIONS && g_sessions[i][0]; i++)
            ;
        if (i == MAX_SESSIONS)
            i = 0;
        new_session_id(g_sessions[i]);
        snprintf(body, sizeof(body), "{\"result\":true,\"session\":\"%s\",\"params\":{\"user\":\"%s\"}}\n", g_sessions[i], user);
    } else {
        snprintf(body, sizeof(body), "{\"result\":false,\"error\":{\"code\":401}}\n");
    }
    send_text(fd, 200, "OK", "application/json", body);
}

/*
 * PWEH-DH-01: "로컬 요청" 판정이 요청 본문 값(클라이언트가 써 넣은 loginType, ipAddr)에만 의존한다.
 */
static int is_local_request(const struct login_req *l)
{
    return strcmp(l->login_type, "Loopback") == 0 && strcmp(l->ip_addr, "127.0.0.1") == 0;
}

static void rpc_global_login(int fd, const char *body, int peer_is_loopback)
{
    struct login_req l;
    memset(&l, 0, sizeof(l));
    json_get(body, "userName", l.user, sizeof(l.user));
    json_get(body, "password", l.pass, sizeof(l.pass));
    json_get(body, "clientType", l.client_type, sizeof(l.client_type));
    json_get(body, "loginType", l.login_type, sizeof(l.login_type));
    json_get(body, "ipAddr", l.ip_addr, sizeof(l.ip_addr));
    if (peer_is_loopback < 0)
        fprintf(stderr, "sonia: peer address unavailable\n");
    /* PWEH-DH-01: peer_is_loopback(실제 소켓 주소) 대신 요청 값으로 판정하고 비밀번호 검증을 건너뛴다 */
    if (is_local_request(&l)) {
        send_login_result(fd, 1, l.user);
        return;
    }
    send_login_result(fd, verify_password(l.user, l.pass), l.user);
}

static void rpc_dispatch_login(int fd, const char *body, int peer_is_loopback)
{
    char method[48] = "";
    json_get(body, "method", method, sizeof(method));
    if (strcmp(method, "global.login") == 0) {
        rpc_global_login(fd, body, peer_is_loopback);
        return;
    }
    send_text(fd, 400, "Bad Request", "application/json", "{\"result\":false}\n");
}

static void rpc_dispatch(int fd, const struct http_req *r)
{
    char method[48] = "";
    json_get(r->body, "method", method, sizeof(method));
    if (strcmp(method, "pweh.getDeviceType") == 0) {
        send_text(fd, 200, "OK", "application/json", "{\"result\":true,\"params\":{\"type\":\"synthetic-ipc\"}}\n");
        return;
    }
    send_text(fd, 200, "OK", "application/json", "{\"result\":false}\n");
}

static void send_file(int fd, const char *path)
{
    char buf[1024];
    char hdr[192];
    ssize_t n;
    int in = open(path, O_RDONLY);
    if (in < 0) {
        send_text(fd, 404, "Not Found", "text/plain", "not found\n");
        return;
    }
    n = snprintf(hdr, sizeof(hdr), "HTTP/1.1 200 OK\r\nServer: %s\r\nContent-Type: application/octet-stream\r\n\r\n", SERVER_NAME);
    if (write(fd, hdr, (size_t)n) < 0) {
        close(in);
        return;
    }
    while ((n = read(in, buf, sizeof(buf))) > 0) {
        if (write(fd, buf, (size_t)n) < 0)
            break;
    }
    close(in);
}

/* PWEH-DH-02: 설정 디렉터리의 파일을 그대로 내려준다 (호출 위치가 세션 확인보다 앞이다) */
static void serve_config_file(int fd, const char *name)
{
    char path[256];
    if (!name[0] || strchr(name, '/') || strstr(name, "..")) {
        send_text(fd, 400, "Bad Request", "text/plain", "bad name\n");
        return;
    }
    snprintf(path, sizeof(path), CONFIG_DIR "%s", name);
    send_file(fd, path);
}

static void http_dispatch(int fd, const struct http_req *r, int peer_is_loopback)
{
    /* PWEH-DH-02: 설정 파일 경로는 세션 확인보다 먼저 처리된다 */
    if (strncmp(r->path, CONFIG_URI_PREFIX, strlen(CONFIG_URI_PREFIX)) == 0) {
        serve_config_file(fd, r->path + strlen(CONFIG_URI_PREFIX));
        return;
    }
    if (strcmp(r->path, RPC_LOGIN_PATH) == 0) {
        rpc_dispatch_login(fd, r->body, peer_is_loopback);
        return;
    }
    if (!session_valid(r)) {
        send_text(fd, 401, "Unauthorized", "application/json", "{\"result\":false}\n");
        return;
    }
    if (strcmp(r->path, RPC_PATH) == 0) {
        rpc_dispatch(fd, r);
        return;
    }
    send_text(fd, 404, "Not Found", "text/plain", "not found\n");
}

static void parse_request(char *buf, struct http_req *r)
{
    char *line, *save = NULL, *body;
    memset(r, 0, sizeof(*r));
    body = strstr(buf, "\r\n\r\n");
    if (body) {
        snprintf(r->body, sizeof(r->body), "%s", body + 4);
        *body = '\0';
    }
    line = strtok_r(buf, "\r\n", &save);
    if (!line)
        return;
    if (sscanf(line, "%7s %255s", r->method, r->path) != 2)
        return;
    while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
        if (strncasecmp(line, "Cookie: ", 8) == 0)
            snprintf(r->cookie, sizeof(r->cookie), "%s", line + 8);
    }
}

static int peer_loopback(int fd)
{
    struct sockaddr_in peer;
    socklen_t len = sizeof(peer);
    if (getpeername(fd, (struct sockaddr *)&peer, &len) < 0)
        return -1;
    return ntohl(peer.sin_addr.s_addr) == INADDR_LOOPBACK;
}

static void handle_client(int fd)
{
    char buf[MAX_REQ];
    struct http_req r;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0)
        return;
    buf[n] = '\0';
    parse_request(buf, &r);
    http_dispatch(fd, &r, peer_loopback(fd));
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;
    int opt, srv, one = 1;
    struct sockaddr_in sa;

    while ((opt = getopt(argc, argv, "p:")) != -1) {
        if (opt == 'p')
            port = atoi(optarg);
    }
    fprintf(stderr, "%s [%s]\n", SERVER_NAME, pweh_marker);
    signal(SIGCHLD, SIG_IGN);
    srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0)
        return 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(srv, (struct sockaddr *)&sa, sizeof(sa)) < 0 || listen(srv, 8) < 0) {
        perror("sonia: bind");
        return 1;
    }
    for (;;) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        handle_client(c);
        close(c);
    }
    close(srv);
    return 0;
}
