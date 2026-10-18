/*
 * httpd.c - PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE
 *
 * pweh.mocktarget 합성 카메라 펌웨어에 들어가는 최소 웹 서버.
 * 분석 파이프라인(fwtriage / REA / Ghidra)의 정답(ground truth) 검증을 위해 취약점을
 * "의도적으로" 심었다. 각 취약점은 PWEH-PLANT-xx 주석으로 표시했고, 같은 목록이 펌웨어
 * 매니페스트(<image>.manifest.json)의 planted_issues 에 들어 있다.
 *
 * 이 코드는 실제 벤더 코드가 아니며, 토큰/계정/비밀번호는 모두 합성 값이다.
 * 실제 네트워크에서 실행하지 말 것. (시뮬레이터는 이 바이너리를 실행하지 않는다 — 정적 분석 대상이다.)
 *
 * 빌드: zig cc -target arm-linux-musleabi|mipsel-linux-musleabi -static -O2 -o httpd httpd.c
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PWEH_MARKER "PWEH SYNTHETIC TEST FIRMWARE - NOT VENDOR CODE"
#define SERVER_NAME "ipcam-httpd/1.0 (pweh synthetic)"
#define DEFAULT_PORT 80
#define DEFAULT_ROOT "/var/www"
#define MAX_REQ 4096

/* PWEH-PLANT-04: 하드코딩된 관리자 계정 (합성 값) */
#define ADMIN_USER "admin"
#define ADMIN_PASS "pweh-synth-admin-0000"

/* PWEH-PLANT-01: 인증 검사가 받아 주는 하드코딩된 서비스(백도어) 토큰 (합성 값) */
static const char *k_service_token = "PWEH-SYNTHETIC-BACKDOOR-TOKEN-7f3a9c";

/* 내부 자가 점검 요청에 쓰는 고정 자격증명 헤더 (admin:pweh-synth-admin-0000) */
static const char *k_selftest_auth = "Authorization: Basic YWRtaW46cHdlaC1zeW50aC1hZG1pbi0wMDAw";

const char pweh_marker[] = PWEH_MARKER;

struct request {
    char method[8];
    char path[256];
    char query[512];
    char auth[256];
    char token[128];
};

static const char *g_root = DEFAULT_ROOT;

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
        } else if (*src == '+') {
            dst[o++] = ' ';
            src++;
        } else {
            dst[o++] = *src++;
        }
    }
    dst[o] = '\0';
}

static int get_param(const char *query, const char *name, char *out, size_t outlen)
{
    size_t nlen = strlen(name);
    const char *p = query;
    while (p && *p) {
        if (strncmp(p, name, nlen) == 0 && p[nlen] == '=') {
            char raw[256];
            const char *v = p + nlen + 1;
            size_t i = 0;
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

static int base64_decode(const char *in, char *out, size_t outlen)
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

static void send_text(int fd, int code, const char *status, const char *ctype, const char *body)
{
    char hdr[512];
    int n = snprintf(hdr, sizeof(hdr),
                     "HTTP/1.0 %d %s\r\nServer: %s\r\nContent-Type: %s\r\nContent-Length: %u\r\n\r\n",
                     code, status, SERVER_NAME, ctype, (unsigned)strlen(body));
    if (write(fd, hdr, (size_t)n) < 0)
        return;
    if (write(fd, body, strlen(body)) < 0)
        return;
}

static void send_error(int fd, int code, const char *msg)
{
    send_text(fd, code, code == 401 ? "Unauthorized" : (code == 404 ? "Not Found" : "Bad Request"),
              "text/plain", msg);
}

static void send_file(int fd, const char *path, const char *ctype)
{
    char buf[1024];
    char hdr[256];
    ssize_t n;
    int in = open(path, O_RDONLY);
    if (in < 0) {
        send_error(fd, 404, "not found\n");
        return;
    }
    n = snprintf(hdr, sizeof(hdr), "HTTP/1.0 200 OK\r\nServer: %s\r\nContent-Type: %s\r\n\r\n", SERVER_NAME, ctype);
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

/*
 * PWEH-PLANT-02: 정적 리소스로 "보이는" 경로는 인증을 건너뛴다.
 * 정규화 전 URI 원문에 대해 접두어/부분 문자열 비교를 하므로
 * "/cgi-bin/ping.cgi?x=.css" 나 "/static/../cgi-bin/..." 같은 요청도 무인증으로 통과한다.
 */
static int is_static_resource(const char *path)
{
    if (strncmp(path, "/static/", 8) == 0)
        return 1;
    if (strstr(path, ".css") || strstr(path, ".js") || strstr(path, ".png") || strstr(path, ".jpg"))
        return 1;
    return 0;
}

/* PWEH-PLANT-04: 고정 관리자 계정과 비교 */
static int check_credentials(const char *user, const char *pass)
{
    if (strcmp(user, ADMIN_USER) == 0 && strcmp(pass, ADMIN_PASS) == 0)
        return 1;
    return 0;
}

static int check_auth(const struct request *req)
{
    char decoded[256];
    char *colon;

    if (is_static_resource(req->path))          /* PWEH-PLANT-02 */
        return 1;
    if (req->token[0] && strcmp(req->token, k_service_token) == 0)   /* PWEH-PLANT-01 */
        return 1;
    if (strncmp(req->auth, "Basic ", 6) != 0)
        return 0;
    if (base64_decode(req->auth + 6, decoded, sizeof(decoded)) < 0)
        return 0;
    colon = strchr(decoded, ':');
    if (!colon)
        return 0;
    *colon = '\0';
    return check_credentials(decoded, colon + 1);
}

/*
 * PWEH-PLANT-03: CGI 핸들러가 요청 파라미터(host)를 검증 없이 셸 명령에 넣고 system() 으로 실행한다.
 * 예) /cgi-bin/ping.cgi?host=127.0.0.1;id
 */
static void handle_ping_cgi(int fd, const struct request *req)
{
    char host[128];
    char cmd[256];

    if (!get_param(req->query, "host", host, sizeof(host))) {
        send_error(fd, 400, "missing host\n");
        return;
    }
    snprintf(cmd, sizeof(cmd), "ping -c 1 %s > /tmp/ping.log 2>&1", host);
    system(cmd);
    send_file(fd, "/tmp/ping.log", "text/plain");
}

static void handle_status_cgi(int fd)
{
    char body[256];
    char up[64] = "0.00 0.00";
    FILE *f = fopen("/proc/uptime", "r");
    if (f) {
        if (!fgets(up, sizeof(up), f))
            strcpy(up, "0.00 0.00");
        fclose(f);
    }
    snprintf(body, sizeof(body), "model=synthetic-ipcam\nuptime=%s", up);
    send_text(fd, 200, "OK", "text/plain", body);
}

static void handle_login_cgi(int fd, const struct request *req)
{
    char user[64] = "", pass[64] = "";
    get_param(req->query, "user", user, sizeof(user));
    get_param(req->query, "pass", pass, sizeof(pass));
    if (check_credentials(user, pass))
        send_text(fd, 200, "OK", "text/plain", "login ok\n");
    else
        send_error(fd, 401, "login failed\n");
}

/* 자가 점검: 루프백으로 상태 페이지를 요청한다 (고정 자격증명 사용) */
static int selftest(int port)
{
    char req[256];
    struct sockaddr_in sa;
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0)
        return -1;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((unsigned short)port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(s);
        return -1;
    }
    snprintf(req, sizeof(req), "GET /cgi-bin/status.cgi HTTP/1.0\r\n%s\r\n\r\n", k_selftest_auth);
    if (write(s, req, strlen(req)) < 0) {
        close(s);
        return -1;
    }
    close(s);
    return 0;
}

static void parse_request(char *buf, struct request *req)
{
    char *line, *save = NULL, *q;
    memset(req, 0, sizeof(*req));
    line = strtok_r(buf, "\r\n", &save);
    if (!line)
        return;
    sscanf(line, "%7s %255s", req->method, req->path);
    q = strchr(req->path, '?');
    if (q) {
        *q = '\0';
        strncpy(req->query, q + 1, sizeof(req->query) - 1);
    }
    while ((line = strtok_r(NULL, "\r\n", &save)) != NULL) {
        if (strncasecmp(line, "Authorization: ", 15) == 0)
            strncpy(req->auth, line + 15, sizeof(req->auth) - 1);
        else if (strncasecmp(line, "X-Service-Token: ", 17) == 0)
            strncpy(req->token, line + 17, sizeof(req->token) - 1);
    }
    if (!req->token[0])
        get_param(req->query, "token", req->token, sizeof(req->token));
}

static const char *content_type(const char *path)
{
    const char *dot = strrchr(path, '.');
    if (!dot)
        return "application/octet-stream";
    if (strcmp(dot, ".html") == 0)
        return "text/html";
    if (strcmp(dot, ".css") == 0)
        return "text/css";
    if (strcmp(dot, ".js") == 0)
        return "application/javascript";
    if (strcmp(dot, ".png") == 0)
        return "image/png";
    return "application/octet-stream";
}

static void handle_client(int fd)
{
    char buf[MAX_REQ];
    char full[512];
    struct request req;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    if (n <= 0)
        return;
    buf[n] = '\0';
    parse_request(buf, &req);

    if (!check_auth(&req)) {
        send_error(fd, 401, "authentication required\n");
        return;
    }
    if (strcmp(req.path, "/cgi-bin/ping.cgi") == 0) {
        handle_ping_cgi(fd, &req);
    } else if (strcmp(req.path, "/cgi-bin/status.cgi") == 0) {
        handle_status_cgi(fd);
    } else if (strcmp(req.path, "/cgi-bin/login.cgi") == 0) {
        handle_login_cgi(fd, &req);
    } else {
        if (strcmp(req.path, "/") == 0)
            snprintf(full, sizeof(full), "%s/index.html", g_root);
        else
            snprintf(full, sizeof(full), "%s%s", g_root, req.path);
        send_file(fd, full, content_type(full));
    }
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT;
    int opt, srv, one = 1;
    struct sockaddr_in sa;

    while ((opt = getopt(argc, argv, "p:h:")) != -1) {
        if (opt == 'p')
            port = atoi(optarg);
        else if (opt == 'h')
            g_root = optarg;
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
        perror("httpd: bind");
        return 1;
    }
    if (fork() == 0) {
        sleep(2);
        _exit(selftest(port) == 0 ? 0 : 1);
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
