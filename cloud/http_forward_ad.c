#include <stdio.h>
#include <ctype.h>
#include <netdb.h> 
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>

//#define HFA_AD_CONTENT      "<div style=\"width:200px;height:100px;border:1px solid red;text-align:center;line-height:100px;\"><a href=\"http://www.winnermicro.com\">W60X Soc WiFi</a></div>"
//#define HFA_AD_CONTENT      "<div style=\"height:50px;border:1px solid red;text-align:center;line-height:50px;\"><a href=\"http://www.winnermicro.com\">W60X Soc WiFi</a></div>"
#define HFA_AD_CONTENT      "<div style=\"width:100%;height:107px;border:0px solid red;text-align:center;line-height:100px;\"><a href=\"http://www.winnermicro.com/html/1//156/158/index.html\"><img style=\"width:100%;height:107px;\" src=\"http://www.wdyichen.cn/test/wm/wm_w600.jpg\" alt=\"W60X Soc WiFi\"></a></div>"


#define HFA_DEBUG
#ifdef HFA_DEBUG
#define HFA_PRINTF          printf
#else
#define HFA_PRINTF(...)
#endif

#define HFA_UPDATE_FILE     "./hfa_list.conf"

#define HFA_UPDATE_PORT     20196
#define HFA_FORWARD_PORT    20198

#define HFA_BUF_LEN_MAX     8196
#define HFA_LINE_BUF_LEN    4096
#define HFA_ADDR_LEN        512

#define HFA_RCV_MAX_TIME    5

#define HFA_CMP_MAX(x, y)    ((x) > (y) ? (x) : (y))

enum hfa_state {
    HFA_STATE_FIND_SRC_HEADER = 0,
    HFA_STATE_FIND_DST_HEADER,
    HFA_STATE_FIND_BODY,
    HFA_STATE_DONE
};

struct hfa_ctx {
    int sfd;
    int dfd;

    char *buf;
    unsigned int content_len;

    enum hfa_state state;
};

#ifdef HFA_DEBUG
static void hfa_dump(unsigned char *p, int len)
{
    int i;

    printf("dump length : %d\n", len);
    for (i = 0; i < len; i++)
    {
        printf("%02X ", p[i]);
        if ((i + 1) % 16 == 0 && (i + 1) % 32 != 0)
        {
            printf("- ");
        }
        if ((i + 1) % 32 == 0)
        {
            printf("\n");
        }
        if (i == 2000)
        {
            printf("\n");
            break;
        }
    }
    printf("\n");
}
#endif

static char *hfa_strcasestr(const char *str1, const char *str2)
{
  char *cp = (char *) str1;
  char *s1, *s2;

  if (!*str2) return (char *) str1;

  while (*cp) {
    s1 = cp;
    s2 = (char *) str2;

    while (*s1 && *s2 && !(tolower((int)*s1) - tolower((int)*s2))) s1++, s2++;
    if (!*s2) return cp;
    cp++;
  }

  return NULL;
}

static char *hfa_trim_space_left(char *p)
{
    while (*p == ' ')
        p++;

    return p;
}

static int hfa_media_filter(char *media)
{
    char *pos;

    if ('/' == media[strlen(media) - 1])
        return 0;

    pos = media + strlen(media) - 1;
    while (pos != media)
    {
        if ('.' == *pos)
        {
            pos++;

            if (!strncasecmp(pos, "html", 4))
                return 0;
            else if (!strncasecmp(pos, "htm", 3))
                return 0;
            else if (!strncasecmp(pos, "php", 3))
                return 0;
            else if (strncasecmp(pos, "asp", 3))
                return 0;

            return 1;
        }

        pos--;
    }

    return 0;/* 没点的多半都是index页 */
}

static int hfa_connection_server(char *address, unsigned short port)
{
	struct hostent *hp;
	struct sockaddr_in server;
	int skt = -1;
	int ret = -1;

    hp = gethostbyname(address);
    if (hp == NULL)
	{
		return -11;
	}

    HFA_PRINTF("get hostbyname ok.\r\n");

	skt = socket(AF_INET, SOCK_STREAM, 0);
	if (skt < 0)
	{
		return -12;
	}

	memset(&server, 0, sizeof(struct sockaddr_in));
	memcpy(&(server.sin_addr), hp->h_addr, hp->h_length);
	server.sin_family = AF_INET;
	server.sin_port = htons(port);

	ret = connect(skt, (struct sockaddr*)&server, sizeof(struct sockaddr));
	if (ret < 0)
	{
		close(skt);
		skt = -14;
	}

	return skt;
}

static int hfa_parse_address(char* host, char *address, unsigned short* portNum)
{
	char* from = NULL ;
	char* to = NULL;
	int i;
	int portNumInt;
	char nextChar;

	from = &host[0];
	to = &address[0];
	for (i = 0; i < HFA_ADDR_LEN; ++i)
	{
		if (*from == '\0' || *from == ':' || *from == '/')
		{
			*to = '\0';
			break;
		}
		*to++ = *from++;
	}
	if (i == HFA_ADDR_LEN)
	{
		return -8;
	}

 	*portNum = 80;
	nextChar = *from;
	if (nextChar == ':')
	{

		if (sscanf(++from, "%d", &portNumInt) != 1)
		{
			return -9;
		}
		if (portNumInt < 1 || portNumInt > 65535)
		{
			return -10;
		}
		*portNum = portNumInt;
	}

	return 0;
}

static int hfa_parse_media(char *head, char *media)
{
    char *pos;
    char *end;

    pos = strchr(head, ' ');
    if (!pos)
        return -1;

    do
    {
        pos++;
    } while (' ' == *pos);

    end = hfa_strcasestr(pos, " HTTP/1.");
    if (!end)
        return -2;

    do
    {
        end--;
    } while (' ' == *end);

    end++;
    memcpy(media, pos, end - pos);
    media[end - pos] = '\0';

    return 0;
}

static int hfa_recv(int skt, void *html, int len)
{
    int ret;
    fd_set read_set;
    struct timeval tv;

    FD_ZERO(&read_set);
    FD_SET(skt, &read_set);
    tv.tv_sec  = HFA_RCV_MAX_TIME;
    tv.tv_usec = 0;

    ret = select(skt + 1, &read_set, NULL, NULL, &tv);
    if (ret > 0)
    {
        if (FD_ISSET(skt, &read_set))
        {
            ret = recv(skt, html, len, 0);
#if 0
            if (0 == ret)
            {
                ret = -16;
            }
            else if (ret < 0)
            {

            }
#endif
            FD_CLR(skt, &read_set);
        }
        else
        {
            ret = -17;
        }
    }
    else
    {
        ret = -18;
    }

    return ret;
}

static void hfa_parse_line(struct hfa_ctx *ctx, char* line, unsigned short len)
{
    if (sscanf(line, "Content-Length: %u", &ctx->content_len) == 1 ||
	    sscanf(line, "Content-length: %u", &ctx->content_len) == 1)
	{

	}

    return;
}


static int hfa_get_response(struct hfa_ctx *ctx, int fd)
{
    int line_count, total_len = 0;
    int len;
    char *buf, *q;
    unsigned char ch;
    int ret;

    buf = malloc(HFA_LINE_BUF_LEN);
    if (!buf)
    {
        return -2;
    }

    line_count = 0;
    memset(ctx->buf, 0, HFA_BUF_LEN_MAX);
    for(;;) {
        memset(buf, 0, HFA_LINE_BUF_LEN);
        q = buf;
        for(;;) {
            ret = hfa_recv(fd, &ch, 1);
            if (ret <= 0)
        	    break;
            if (ch == '\n')
                break;
            else if (ch != '\r') {
                if ((q - buf) < HFA_LINE_BUF_LEN - 1)
                    *q++ = ch;
            }
        }
        *q = '\0';

        //HFA_PRINTF("line = [%s]\r\n", buf);

        /* test if last line */
        if (buf[0] == '\0')
        {
            *(ctx->buf + total_len) = '\0';
            break;
        }

        if (line_count == 0) {
            *q++ = '\r';
            *q   = '\n';
            total_len  = q - buf + 1;
            memcpy(ctx->buf, buf, total_len);
        }
        else
        {
            *q++ = '\r';
            *q   = '\n';
            len = q - buf + 1;
            memcpy(ctx->buf + total_len, buf, len);
            total_len += len;
            hfa_parse_line(ctx, buf, len);
        }
        line_count++;
    }

    free(buf);

    if (total_len > 0)
    {
        ctx->buf[total_len++] = '\r';
        ctx->buf[total_len++] = '\n';
        //hfa_dump(ctx->buf, total_len);
    }

	return total_len;
}

static int hfa_proc_state_1(struct hfa_ctx *ctx)
{
    int ret;
    char *pos;
    char *end;
    char *host = NULL;
    char *addr = NULL;
    char *media = NULL;
    char *head = NULL;
    unsigned short port;

    ret = hfa_get_response(ctx, ctx->sfd);
    if (ret <= 0)
        return -1;//break;

    HFA_PRINTF("---> src = [%s]\r\n\r\n", ctx->buf);

    if (-1 == ctx->dfd)
    {
        pos = hfa_strcasestr(ctx->buf, "host:");
        if (!pos)
            return -1;//break;

        pos += strlen("host:");
        pos = hfa_trim_space_left(pos);
        end = strstr(pos, "\r\n");
        if (!end)
            return -1;//break;

        host = malloc(end - pos + 1);
        addr = malloc(HFA_ADDR_LEN);

        if (!host || !addr)
        {
            free(host);
            free(addr);
            return -1;//break;
        }

        memcpy(host, pos, end - pos);
        host[end - pos] = '\0';

        if (hfa_parse_address(host, addr, &port))
        {
            free(host);
            free(addr);
            return -1;//break;
        }

        HFA_PRINTF("host = '%s', addr = '%s', port = %hu.\r\n", host, addr, port);

        free(host);
        ctx->dfd = hfa_connection_server(addr, port);
        free(addr);
        if (ctx->dfd < 0)
        {
            return -1;//break;
        }

        HFA_PRINTF("connect server = %d.\r\n", ctx->dfd);
    }

    if (strncasecmp(ctx->buf, "GET ", 4))
    {
        ret = send(ctx->dfd, ctx->buf, ret, 0);
        if (ret <= 0)
        {
            close(ctx->dfd);
            return -1;//break;
        }

        ctx->state = HFA_STATE_DONE;
        return 0;//continue;
    }

    media = malloc(HFA_ADDR_LEN);
    if (!media)
    {
        close(ctx->dfd);
        return -1;//break;
    }
    
    if (hfa_parse_media(ctx->buf, media))
    {
        free(media);
        close(ctx->dfd);
        return -1;//break;
    }

    HFA_PRINTF("media = '%s'.\r\n", media);

    if (hfa_media_filter(media))
    {
        free(media);
        ret = send(ctx->dfd, ctx->buf, ret, 0);
        if (ret <= 0)
        {
            close(ctx->dfd);
            return -1;//break;
        }

        ctx->state = HFA_STATE_DONE;
        return 0;//continue;
    }

    free(media);

    head = malloc(ret + 1);
    if (!head)
    {
        close(ctx->dfd);
        return -1;//break;
    }

    pos = hfa_strcasestr(ctx->buf, "Accept-Encoding:");
    if (!pos)
    {
        strcpy(head, ctx->buf);
    }
    else
    {
        end = strstr(pos, "\r\n");
        if (!end)
        {
            close(ctx->dfd);
            free(head);
            return -1;//break;
        }

        end += strlen("\r\n");
        memcpy(head, ctx->buf, pos - ctx->buf);
        memcpy(head + (pos - ctx->buf), end, ret - (end - ctx->buf));

        HFA_PRINTF("ret = %d, new = %d, %d, %d\r\n", ret, ret - (end - pos), pos - ctx->buf, end - ctx->buf);
        HFA_PRINTF("---> fwd = [%s]\r\n\r\n", head);
        //hfa_dump((unsigned char *)head, strlen(head));
        //HFA_PRINTF("fwd len = %d.\r\n", ret - (end - pos));

        ret = send(ctx->dfd, head, ret - (end - pos), 0);
        free(head);
        if (ret <= 0)
        {
            close(ctx->dfd);
            return -1;//break;
        }

        ctx->state = HFA_STATE_FIND_DST_HEADER;
    }

    return 0;
}

static int hfa_proc_state_2(struct hfa_ctx *ctx)
{
    int ret;
    int len;
    char *pos;
    char *end;
    char *head = NULL;
    fd_set read_set;
	int maxfd;

    maxfd = HFA_CMP_MAX(ctx->sfd, ctx->dfd);
    FD_ZERO(&read_set);
    FD_SET(ctx->sfd, &read_set);
    FD_SET(ctx->dfd, &read_set);
    ret = select(maxfd + 1, &read_set, NULL, NULL, NULL);
    if (ret > 0)
    {
        if (FD_ISSET(ctx->sfd, &read_set))
        {
            HFA_PRINTF("state[%d]: recv from sfd\r\n", ctx->state);
        
            ret = recv(ctx->sfd, ctx->buf, HFA_BUF_LEN_MAX, 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            ret = send(ctx->dfd, ctx->buf, ret, 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            //FD_CLR(ctx->sfd, read_set);
        }

        if (FD_ISSET(ctx->dfd, &read_set))
        {
            HFA_PRINTF("state[%d]: recv from dfd\r\n", ctx->state);

            ret = hfa_get_response(ctx, ctx->dfd);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            HFA_PRINTF("<--- src = [%s]\r\n\r\n", ctx->buf);

            /* change content len: add ad len */
            pos = hfa_strcasestr(ctx->buf, "Content-Length:");
            if (!pos)/* 没有可能是chunked方式传递的，暂不处理 */
            {
                ret = send(ctx->sfd, ctx->buf, ret, 0);
                if (ret <= 0)
                {
                    close(ctx->dfd);
                    return -1;//break;
                }

                ctx->state = HFA_STATE_DONE;
                return 0;//continue;
            }

            end = strstr(pos, "\r\n");
            if (!end)
            {
                close(ctx->dfd);
                return -1;//break;
            }
            end += strlen("\r\n");

            head = malloc(ret + 16);
            if (!head)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            len = pos - ctx->buf;
            memcpy(head, ctx->buf, len);
            len += sprintf(head + len, "Content-Length: %u\r\n", ctx->content_len + strlen(HFA_AD_CONTENT));
            memcpy(head + len, end, ret - (end - ctx->buf));
            len += ret - (end - ctx->buf);

            HFA_PRINTF("ret = %d, new = %d, %d, %d\r\n", ret, len, pos - ctx->buf, end - ctx->buf);
            head[len] = '\0';
            HFA_PRINTF("<--- fwd = [%s]\r\n\r\n", head);

            ret = send(ctx->sfd, head, len, 0);
            free(head);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            ctx->state = HFA_STATE_FIND_BODY;

            //FD_CLR(ctx->dfd, read_set);
        }
    }
    else
    {
        /* 应该不会走到这儿 */
    }

    return 0;
}

static int hfa_proc_state_3(struct hfa_ctx *ctx)
{
    int ret;
    int len;
    char *pos;
    char *end;

    len = recv(ctx->dfd, ctx->buf, HFA_BUF_LEN_MAX - 1, 0);
    if (len <= 0)
    {
        close(ctx->dfd);
        return -1;//break;
    }

    ctx->buf[len] = '\0';
    HFA_PRINTF("<--- body %d = [%s]\r\n\r\n", len, ctx->buf);

    /* find <body>: add ad */
    pos = strstr(ctx->buf, "<body");
    if (pos)
    {
        end = strchr(pos, '>');
        if (end)
        {
            end++;

            ret = send(ctx->sfd, ctx->buf, end - ctx->buf, 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            ret = send(ctx->sfd, HFA_AD_CONTENT, strlen(HFA_AD_CONTENT), 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            ret = send(ctx->sfd, ctx->buf + (end - ctx->buf),  len - (end - ctx->buf), 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            HFA_PRINTF("---> ad insert body sent\r\n\r\n");

            ctx->state = HFA_STATE_DONE;

            return 0;//continue;
        }
    }

    HFA_PRINTF("---> body hold send\r\n\r\n");
    ret = send(ctx->sfd, ctx->buf, len, 0);
    if (ret <= 0)
    {
        close(ctx->dfd);
        return -1;//break;
    }

    ctx->state = HFA_STATE_DONE;/* 暂且不用考虑接收不全继续的情况 */

    return 0;
}

static int hfa_proc_state_4(struct hfa_ctx *ctx)
{
    int ret;
    fd_set read_set;
	int maxfd;

    maxfd = HFA_CMP_MAX(ctx->sfd, ctx->dfd);
    FD_ZERO(&read_set);
    FD_SET(ctx->sfd, &read_set);
    FD_SET(ctx->dfd, &read_set);
    ret = select(maxfd + 1, &read_set, NULL, NULL, NULL);
    if (ret > 0)
    {
        if (FD_ISSET(ctx->sfd, &read_set))
        {
            #if 1
            ret = recv(ctx->sfd, ctx->buf, HFA_BUF_LEN_MAX, 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            ret = send(ctx->dfd, ctx->buf, ret, 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }
            #else
            ctx->state = HFA_STATE_FIND_SRC_HEADER;
            if (hfa_proc_state_1(ctx))
                return -1;//break;
            #endif

            //FD_CLR(ctx->sfd, read_set);
        }

        if (FD_ISSET(ctx->dfd, &read_set))
        {
            ret = recv(ctx->dfd, ctx->buf, HFA_BUF_LEN_MAX, 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            ret = send(ctx->sfd, ctx->buf, ret, 0);
            if (ret <= 0)
            {
                close(ctx->dfd);
                return -1;//break;
            }

            //FD_CLR(ctx->dfd, read_set);
        }
    }
    else
    {
        /* 应该不会走到这儿 */
    }

    return 0;
}

static void *hfa_recv_thread(void *arg)
{
    struct hfa_ctx *ctx;

	pthread_detach(pthread_self());

    ctx = (struct hfa_ctx *)arg;

    HFA_PRINTF("%d thread enter.\r\n", ctx->sfd);

    while (1)
    {
        if (HFA_STATE_FIND_SRC_HEADER == ctx->state)
        {
            if (hfa_proc_state_1(ctx))
                break;
        }
        else if (HFA_STATE_FIND_DST_HEADER == ctx->state)
        {
            if (hfa_proc_state_2(ctx))
                break;
        }
        else if (HFA_STATE_FIND_BODY == ctx->state)
        {
            if (hfa_proc_state_3(ctx))
                break;
        }
        else
        {
            if (hfa_proc_state_4(ctx))
                break;
        }
    }

    HFA_PRINTF("%d thread exit.\r\n", ctx->sfd);

    close(ctx->sfd);
    free(ctx->buf);
    free(ctx);

    return NULL;
}

static void *hfa_update_entry(void *arg)
{
    int ret;
    char *buf;
    char *rsp;
    FILE *fp;
    int fd = (int)arg;
    int cnt = 0;
    char *pos;

    pthread_detach(pthread_self());

    buf = malloc(HFA_ADDR_LEN);
    if (!buf)
    {
        close(fd);
        return NULL;
    }

    ret = recv(fd, buf, HFA_ADDR_LEN - 1, 0);
    if (ret > 0)
    {
        buf[ret] = '\0';
        if (0 == strncmp(buf, "get_list", strlen("get_list")))
        {
            fp = fopen(HFA_UPDATE_FILE, "r");
            if (fp)
            {
                rsp = malloc(HFA_LINE_BUF_LEN);
                if (rsp)
                {
                    memset(rsp, 0, HFA_LINE_BUF_LEN);
                    pos = rsp + 1;
                    while (fgets(buf, HFA_ADDR_LEN, fp))
                    {
                        cnt++;
                        *pos++ = strlen(buf);
                        strcpy(pos, buf);
                        pos += strlen(buf);
                    }

                    rsp[0] = cnt;
                    ret = send(fd, rsp, pos - rsp, 0);
                    if (ret > 0)
                    {
                        HFA_PRINTF("send %d list ok\r\n", cnt);
                    }
                    else
                    {
                        HFA_PRINTF("send %d list failed\r\n", cnt);
                    }
                    free(rsp);
                }

                fclose(fp);
            }
        }
    }

    free(buf);
    close(fd);

    return NULL;
}

static void *hfa_update_thread(void *arg)
{
    int ret;
    int fd;
    pthread_t pid;
    struct sockaddr_in sraddr;

    pthread_detach(pthread_self());

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        exit(-1);

    memset(&sraddr, 0, sizeof(sraddr));
    sraddr.sin_family = AF_INET;
    sraddr.sin_port = htons(HFA_UPDATE_PORT);
    sraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = bind(fd, (struct sockaddr *)&sraddr, sizeof(sraddr));
    if (ret < 0)
    {
        close(fd);
        exit(-2);
    }

    ret = listen(fd, SOMAXCONN);
    if (ret < 0)
    {
        close(fd);
        exit(-3);
    }

    while (1)
    {
        ret = accept(fd, NULL, NULL);
        if (ret < 0)
        {
            continue;
        }

        if (pthread_create(&pid, NULL, hfa_update_entry, (void *)ret) < 0)
        {
            close(ret);
        }
    }

    return NULL;
}

int main(int argc, char *argv[])
{
    int ret;
    int fd;
    pthread_t pid;
    struct hfa_ctx *ctx;
    struct sockaddr_in sraddr;

    ret = pthread_create(&pid, NULL, hfa_update_thread, NULL);
    if (ret < 0)
        return ret;

    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0)
        return -1;

    memset(&sraddr, 0, sizeof(sraddr));
    sraddr.sin_family = AF_INET;
    sraddr.sin_port = htons(HFA_FORWARD_PORT);
    sraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    ret = bind(fd, (struct sockaddr *)&sraddr, sizeof(sraddr));
    if (ret < 0)
    {
        close(fd);
        return -2;
    }

    ret = listen(fd, SOMAXCONN);
    if (ret < 0)
    {
        close(fd);
        return -3;
    }

    signal(SIGPIPE, SIG_IGN);
    HFA_PRINTF("server running..\r\n");

    while (1)
    {
        ret = accept(fd, NULL, NULL);
        if (ret < 0)
        {
            continue;
        }

        ctx = malloc(sizeof(struct hfa_ctx));
        if (!ctx)
        {
            close(ret);
            continue;
        }

        memset(ctx, 0, sizeof(struct hfa_ctx));

        ctx->buf = malloc(HFA_BUF_LEN_MAX);
        if (!ctx->buf)
        {
            free(ctx);
            close(ret);
            continue;
        }
        
        ctx->sfd = ret;
        ctx->dfd = -1;

        ret = pthread_create(&pid, NULL, hfa_recv_thread, ctx);
        if (ret < 0)
        {
            free(ctx->buf);
            free(ctx);
            close(ctx->sfd);
        }
    }

    HFA_PRINTF("server exit...\r\n");

    return 0;
}

