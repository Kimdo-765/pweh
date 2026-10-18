/*
 * davinci_like.c - PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE
 *
 * pweh.mocktarget 'hikvision-like' 프로필의 합성 메인 앱 (/usr/bin/davinci).
 * 이름(davinci), 배너 형식(App-webs/), API 핸들러 계열 이름(ISAPI / PSIA / SDK / HikCGI 형 경로)은
 * docs/references/cctv-vuln-patterns.md §3.1·§4.1 에 공개된 "펌웨어 쪽 지표"만 빌렸다.
 * 코드는 처음부터 새로 쓴 합성 코드이며 실제 벤더 코드·키·자격증명·요청 형식을 담지 않는다.
 * 시뮬레이터는 이 바이너리를 실행하지 않는다 (정적 분석 대상). 실제 네트워크에서 실행하지 말 것.
 *
 * 분석 파이프라인 정답(ground truth) 검증용으로 "의도적으로" 심은 취약점 클래스
 * (같은 id 가 펌웨어 매니페스트 planted_issues 에 있다):
 *   PWEH-HIK-01  HikCGI 형 핸들러 계열에만 있는 디버그 분기. 합성 매직 파라미터가 있으면 base64 로 디코드한
 *                사용자 이름만으로 신원을 정하고 비밀번호는 확인하지 않는다. 다른 세 계열은 같은 자리에서
 *                basic_auth_check 를 부른다 (핸들러 간 인증 비대칭, 패턴 P4, CVE-2017-7921 계열).
 *   PWEH-HIK-02  언어 설정 핸들러가 요청 본문의 language 값을 검증 없이 셸 명령 문자열에 넣어 system() 으로
 *                실행하고, 디스패처가 이 핸들러를 인증 검사보다 먼저 부른다 (패턴 P11, CVE-2021-36260 계열).
 * 비밀번호는 런타임 계정 파일에서만 읽는다 (바이너리에 고정 자격증명 없음).
 *
 * 빌드: zig cc -target arm-linux-musleabi -static -O2 -fno-inline -o davinci davinci_like.c
 */
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define PWEH_MARKER "PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE"
#define SERVER_BANNER "App-webs/"            /* 공개 서버 배너 형식 (벤더 계열 식별용 지표) */
#define DEFAULT_PORT 8080
#define USERS_DB "/home/config/users.db"    /* 장치 활성화 때 만들어지는 런타임 계정 파일 (rootfs 에 없음) */
#define I18N_ROOT "/usr/share/webroot/i18n"
#define MAGIC_PARAM "pweh_synth_auth"        /* PWEH-HIK-01: 합성 매직 파라미터 이름 */
#define MAX_REQ 4096

const char pweh_marker[] = PWEH_MARKER;

struct request {
    char method[8];
    char path[256];
    char query[512];
    char auth[256];
    char body[1024];
};

typedef int (*auth_fn)(const struct request *req, char *user, size_t userlen);
typedef void (*handler_fn)(int fd, const struct request *req, const char *user);

struct api_family {
    const char *prefix;
    const char *name;
    auth_fn auth;
    handler_fn handler;
};

static int hexval(int c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    c = tolower(c);
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    return -1;
}

static void url_decode(char *dst, const char *src, size_t dstlen)
{
    size_t o = 0;
    while (*src && o + 1 < dstlen) {
        if (*src == '%' && hexval(src[1]) >= 0 && hexval(src[2]) >= 0) {
            dst[o++] = (char)(hexval(src[1]) * 16 + hexval(src[2]));
            src += 3;
        } else {
            dst[o++] = *src++;
        }
    }
    dst[o] = '\0';
}

static int query_param(const char *query, const char *name, char *out, size_t outlen)
{
    size_t nlen = strlen(name);
    const char *p = query;
    while (p && *p) {
        if (strncmp(p, name, nlen) == 0 && p[nlen] == '=') {
            char raw[256];
            size_t i = 0;
            const char *v = p + nlen + 1;
            while (v[i] && v[i] != '&' && i + 1 < sizeof(raw)) {
                raw[i] = v[i];
                i++;
            }
            raw[i] = '\0';
            url_decode(out, raw, outlen);
            return 1;
        }
        p = strchr(p, '&');
        if (p)
            p++;
    }
    return 0;
}

static int b64val(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

static int b64_decode(const char *in, char *out, size_t outlen)
{
    size_t o = 0;
    int acc = 0, bits = 0;
    for (; *in && *in != '='; in++) {
        int v = b64val((unsigned char)*in);
        if (v < 0)
            continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o + 1 >= outlen)
                return -1;
            out[o++] = (char)((acc >> bits) & 0xff);
        }
    }
    out[o] = '\0';
    return (int)o;
}

/* 비밀번호 비교용 합성 다이제스트 (FNV-1a 64) — 저장 값은 런타임 계정 파일에만 있다 */
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
    FILE *f = fopen(USERS_DB, "r");
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

/* 표준 경로: Authorization: Basic 헤더의 사용자/비밀번호를 런타임 계정 파일과 대조한다 */
static int basic_auth_check(const struct request *req, char *user, size_t userlen)
{
    char decoded[192];
    char *colon;
    if (strncmp(req->auth, "Basic ", 6) != 0)
        return 0;
    if (b64_decode(req->auth + 6, decoded, sizeof(decoded)) <= 0)
        return 0;
    colon = strchr(decoded, ':');
    if (!colon)
        return 0;
    *colon = '\0';
    if (!verify_password(decoded, colon + 1))
        return 0;
    snprintf(user, userlen, "%s", decoded);
    return 1;
}

static int isapi_auth(const struct request *req, char *user, size_t userlen)
{
    return basic_auth_check(req, user, userlen);
}

static int psia_auth(const struct request *req, char *user, size_t userlen)
{
    return basic_auth_check(req, user, userlen);
}

static int sdk_auth(const struct request *req, char *user, size_t userlen)
{
    return basic_auth_check(req, user, userlen);
}

/*
 * PWEH-HIK-01: HikCGI 형 계열에만 남은 디버그 분기.
 * 매직 파라미터가 "있기만 하면" 그 값을 base64 디코드해 ':' 앞의 사용자 이름을 신원으로 삼고
 * 비밀번호(':' 뒤)는 버린다. verify_password 를 부르지 않는다.
 */
static int hikcgi_auth(const struct request *req, char *user, size_t userlen)
{
    char enc[160];
    char decoded[160];
    char *colon;
    if (query_param(req->query, MAGIC_PARAM, enc, sizeof(enc))) {
        if (b64_decode(enc, decoded, sizeof(decoded)) > 0) {
            colon = strchr(decoded, ':');
            if (colon)
                *colon = '\0';
            snprintf(user, userlen, "%s", decoded);
            return 1;
        }
    }
    return basic_auth_check(req, user, userlen);
}

static void send_status(int fd, int code, const char *status, const char *ctype, const char *body)
{
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr), "HTTP/1.1 %d %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %u\r\n\r\n",
                     code, status, SERVER_BANNER, ctype, (unsigned)strlen(body));
    if (n > 0 && write(fd, hdr, (size_t)n) < 0)
        return;
    if (write(fd, body, strlen(body)) < 0)
        return;
}

static void isapi_handler(int fd, const struct request *req, const char *user)
{
    char body[256];
    if (strcmp(req->path, "/ISAPI/System/deviceInfo") == 0) {
        snprintf(body, sizeof(body), "<DeviceInfo><model>synthetic-ipc</model><user>%s</user></DeviceInfo>\n", user);
        send_status(fd, 200, "OK", "application/xml", body);
        return;
    }
    send_status(fd, 404, "Not Found", "text/plain", "not found\n");
}

static void psia_handler(int fd, const struct request *req, const char *user)
{
    (void)user;
    if (strcmp(req->path, "/PSIA/System/deviceInfo") == 0) {
        send_status(fd, 200, "OK", "application/xml", "<DeviceInfo><model>synthetic-ipc</model></DeviceInfo>\n");
        return;
    }
    send_status(fd, 404, "Not Found", "text/plain", "not found\n");
}

static void sdk_handler(int fd, const struct request *req, const char *user)
{
    (void)user;
    if (strcmp(req->path, "/SDK/activateStatus") == 0) {
        send_status(fd, 200, "OK", "application/xml", "<Activate><status>activated</status></Activate>\n");
        return;
    }
    send_status(fd, 404, "Not Found", "text/plain", "not found\n");
}

static void hikcgi_handler(int fd, const struct request *req, const char *user)
{
    char body[256];
    if (strcmp(req->path, "/Security/users") == 0) {
        /* 사용자 목록 (관리자 권한 기능) */
        snprintf(body, sizeof(body), "<UserList><User><userName>%s</userName></User></UserList>\n", user);
        send_status(fd, 200, "OK", "application/xml", body);
        return;
    }
    if (strcmp(req->path, "/System/deviceInfo") == 0) {
        send_status(fd, 200, "OK", "application/xml", "<DeviceInfo><model>synthetic-ipc</model></DeviceInfo>\n");
        return;
    }
    send_status(fd, 404, "Not Found", "text/plain", "not found\n");
}

static const struct api_family g_families[] = {
    {"/ISAPI/", "ISAPI", isapi_auth, isapi_handler},
    {"/PSIA/", "PSIA", psia_auth, psia_handler},
    {"/SDK/", "SDK", sdk_auth, sdk_handler},
    {"/Security/", "HikCGI", hikcgi_auth, hikcgi_handler},
    {"/System/", "HikCGI", hikcgi_auth, hikcgi_handler},
};

/* 요청 본문(XML)에서 <name>값</name> 을 꺼낸다 (합성: 아주 단순한 파서) */
static int xml_value(const char *body, const char *name, char *out, size_t outlen)
{
    char open_tag[48], close_tag[48];
    const char *s, *e;
    size_t n;
    snprintf(open_tag, sizeof(open_tag), "<%s>", name);
    snprintf(close_tag, sizeof(close_tag), "</%s>", name);
    s = strstr(body, open_tag);
    if (!s)
        return 0;
    s += strlen(open_tag);
    e = strstr(s, close_tag);
    if (!e)
        return 0;
    n = (size_t)(e - s);
    if (n + 1 > outlen)
        n = outlen - 1;
    memcpy(out, s, n);
    out[n] = '\0';
    return 1;
}

/*
 * PWEH-HIK-02: 언어 묶음 전환. language 값을 화이트리스트로 확인하지 않고 셸 명령 문자열에 끼워 넣어
 * system() 으로 실행한다. 이 핸들러는 dispatch() 에서 인증 검사보다 먼저 불린다.
 */
static void handle_web_language(int fd, const struct request *req)
{
    char lang[64];
    char cmd[256];
    if (!xml_value(req->body, "language", lang, sizeof(lang))) {
        send_status(fd, 400, "Bad Request", "text/plain", "missing language\n");
        return;
    }
    snprintf(cmd, sizeof(cmd), "cp -rf " I18N_ROOT "/%s/* /tmp/i18n/ 2>/dev/null", lang);
    system(cmd);
    send_status(fd, 200, "OK", "application/xml", "<ResponseStatus><statusCode>1</statusCode></ResponseStatus>\n");
}

static void dispatch(int fd, const struct request *req)
{
    char user[64] = "";
    size_t i;

    /* 로그인 화면에서도 언어를 바꿀 수 있게 인증보다 먼저 처리한다 (PWEH-HIK-02 의 전제) */
    if (strcmp(req->path, "/SDK/webLanguage") == 0) {
        handle_web_language(fd, req);
        return;
    }
    for (i = 0; i < sizeof(g_families) / sizeof(g_families[0]); i++) {
        const struct api_family *fam = &g_families[i];
        if (strncmp(req->path, fam->prefix, strlen(fam->prefix)) == 0) {
            if (!fam->auth(req, user, sizeof(user))) {
                send_status(fd, 401, "Unauthorized", "text/plain", "authentication required\n");
                return;
            }
            fam->handler(fd, req, user);
            return;
        }
    }
    send_status(fd, 404, "Not Found", "text/plain", "not found\n");
}

static void parse_request(char *buf, struct request *req)
{
    char *line, *save = NULL, *q, *body;
    memset(req, 0, sizeof(*req));
    body = strstr(buf, "\r\n\r\n");
    if (body) {
        snprintf(req->body, sizeof(req->body), "%s", body + 4);
        *body = '\0';
    }
    line = strtok_r(buf, "\r\n", &save);
    if (!line)
        return;
    if (sscanf(line, "%7s %255s", req->method, req->path) != 2)
        return;
    q = strchr(req->path, '?');
    if (q) {
        *q = '\0';
        snprintf(req->query, sizeof(req->query), "%s", q + 1);
    }
    while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
        if (strncasecmp(line, "Authorization: ", 15) == 0)
            snprintf(req->auth, sizeof(req->auth), "%s", line + 15);
    }
}

static void handle_client(int fd)
{
    char buf[MAX_REQ];
    struct request req;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0)
        return;
    buf[n] = '\0';
    parse_request(buf, &req);
    dispatch(fd, &req);
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
    fprintf(stderr, "davinci (synthetic) %s [%s]\n", SERVER_BANNER, pweh_marker);
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
        perror("davinci: bind");
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
