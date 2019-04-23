/***************************************************************************** 
* 
* 版权没有，请君自便!
* 
*****************************************************************************/ 
#include <stdio.h>
#include <string.h>
#include "wm_include.h"
#include "wm_netif.h"
#include "wm_sockets.h"
#include "lwip/ip.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/alg.h"

/* -------------------- configure --------------------------- */

#define APSTA_AD_TEST_SSID      "your ssid"
#define APSTA_AD_TEST_PWD       "your password"

#define APSTA_AD_CLOUD_SERVER   "y.wdyichen.cn"
#define APSTA_AD_CLOUD_PORT      20198
#define HFA_UPDATE_PORT          20196

#define APSTA_AD_SOFTAP_SSID    "W60X_AD_SOFTAP"
#define APSTA_AD_SOFTAP_PASSWD  "wohenliubi"

/* ---------------------- configure -------------------------- */

#define APSTA_AD_BUF_SIZE            4096
#define APSTA_AD_URL_LEN             256
#define APSTA_AD_RULES_MAX           128

#define APSTA_AD_DELAY_SEC          (30 * HZ)
#define APSTA_AD_UPDATE_SEC         (3600 * HZ)

#define         APSTA_AD_TASK_PRIO             35
#define         APSTA_AD_TASK_STK_SIZE         512
static OS_STK   apsta_ad_task_stk[APSTA_AD_TASK_STK_SIZE];

#define         APSTA_AD_QUEUE_SIZE            4
static tls_os_queue_t *apsta_ad_task_queue = NULL;

#define         APSTA_AD_CMD_CREATE_SOFTAP    0x1
#define         APSTA_AD_CMD_UPDATE_RULES     0x2

static char apsta_ad_buf[APSTA_AD_BUF_SIZE];
static char apsta_ad_url[APSTA_AD_URL_LEN];

static int apsta_ad_rules_cnt = 0;
static u32 apsta_ad_rules[APSTA_AD_RULES_MAX];
static u32 apsta_ad_rules_dest[APSTA_AD_RULES_MAX];
static u16 apsta_ad_rules_port[APSTA_AD_RULES_MAX];

static tls_os_sem_t *apsta_ad_rules_sem = NULL;
static int apsta_ad_rules_cnt2 = 0;
static u32 apsta_ad_rules2[APSTA_AD_RULES_MAX];

static u32 apsta_ad_cloud_host = 0;

extern int wm_printf(const char *fmt,...);

static void apsta_ad_sta_event(u8 *mac, enum tls_wifi_client_event_type event)
{
    wm_printf("client %M is %s\r\n", mac, event ? "offline" : "online");
}

static void apsta_ad_net_status(u8 status)
{
    struct netif *netif = tls_get_netif();

	switch(status)
	{
	    case NETIF_WIFI_JOIN_FAILED:
	        wm_printf("sta join net failed\n");
			break;
		case NETIF_WIFI_DISCONNECTED:
	        wm_printf("sta net disconnected\n");
			break;
		case NETIF_IP_NET_UP:
            wm_printf("sta ip: %v\n", netif->ip_addr.addr);
            tls_os_queue_send(apsta_ad_task_queue, (void *)APSTA_AD_CMD_CREATE_SOFTAP, 0);
			break;
	    case NETIF_WIFI_SOFTAP_FAILED:
            wm_printf("softap create failed\n");
	        break;
        case NETIF_WIFI_SOFTAP_CLOSED:
            wm_printf("softap closed\n");
	        break;
        case NETIF_IP_NET2_UP:
            wm_printf("softap gateway: %v\n", netif->next->ip_addr.addr);
            tls_os_queue_send(apsta_ad_task_queue, (void *)APSTA_AD_CMD_UPDATE_RULES, 0);
	        break;
		default:
			break;
	}
}

#if NAPT_USE_HOOK
static alg_hook_action_e apsta_ad_hook_input(u8 *ehdr, u16 eth_len)
{
    int i;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(ehdr + 14);
    u8 iphdr_len = (ip_hdr->_v_hl & 0x0F) * 4;
    struct tcp_hdr *tcp_hdr = (struct tcp_hdr *)((u8 *)ip_hdr + iphdr_len);

    tls_os_sem_acquire(apsta_ad_rules_sem, 0);
    if ((tcp_hdr->src == htons(APSTA_AD_CLOUD_PORT)) && 
        (ip_hdr->src.addr == apsta_ad_cloud_host))
    {
        for (i = 0; i < apsta_ad_rules_cnt2; i++)
        {
            if (apsta_ad_rules_port[i] == tcp_hdr->dest)
            {
                ip_hdr->src.addr = apsta_ad_rules_dest[i];
                tcp_hdr->src = htons(80);
            }
        }
    }
    tls_os_sem_release(apsta_ad_rules_sem);

    return ALG_HOOK_ACTION_NORMAL;
}

static alg_hook_action_e apsta_ad_hook_output(u8 *ehdr, u16 eth_len)
{
    int i;
    struct ip_hdr *ip_hdr = (struct ip_hdr *)(ehdr + 14);
    u8 iphdr_len = (ip_hdr->_v_hl & 0x0F) * 4;
    struct tcp_hdr *tcp_hdr = (struct tcp_hdr *)((u8 *)ip_hdr + iphdr_len);

    tls_os_sem_acquire(apsta_ad_rules_sem, 0);
    for (i = 0; i < apsta_ad_rules_cnt2; i++)
    {
        //u8 *ip1 = (u8 *)&ip_hdr->dest.addr;
        //u8 *ip2 = (u8 *)&apsta_ad_rules2[i];
        //printf("output: %d.%d.%d.%d, %d.%d.%d.%d\r\n", ip1[0], ip1[1], ip1[2], ip1[3], ip2[0], ip2[1], ip2[2], ip2[3]);
        if ((tcp_hdr->dest == htons(80)) && 
            (ip_hdr->dest.addr == apsta_ad_rules2[i]))
        {
            apsta_ad_rules_dest[i] = ip_hdr->dest.addr;
            apsta_ad_rules_port[i] = tcp_hdr->src;
            ip_hdr->dest.addr = apsta_ad_cloud_host;
            tcp_hdr->dest = htons(APSTA_AD_CLOUD_PORT);
        }
    }
    tls_os_sem_release(apsta_ad_rules_sem);

    return ALG_HOOK_ACTION_NORMAL;
}
#endif

static void apsta_ad_create_softap(void)
{
	struct tls_softap_info_t apinfo;
	struct tls_ip_info_t ipinfo;

	strcpy((char *)apinfo.ssid, APSTA_AD_SOFTAP_SSID);
	apinfo.encrypt = 6;  /* wpa2-aes */
	apinfo.channel = 10;
	apinfo.keyinfo.format = 1; /* format: 0,hex, 1,ascii */
	apinfo.keyinfo.index = 1;  /* key index */
	apinfo.keyinfo.key_len = strlen(APSTA_AD_SOFTAP_PASSWD); /* key length */
	strcpy((char *)apinfo.keyinfo.key, APSTA_AD_SOFTAP_PASSWD);

	/* ip information: ip address, mask, DNS name */
	ipinfo.ip_addr[0] = 192;
	ipinfo.ip_addr[1] = 168;
	ipinfo.ip_addr[2] = 8;
	ipinfo.ip_addr[3] = 1;
	ipinfo.netmask[0] = 255;
	ipinfo.netmask[1] = 255;
	ipinfo.netmask[2] = 255;
	ipinfo.netmask[3] = 0;
	strcpy((char *)ipinfo.dnsname, "local.w60x");
	tls_wifi_softap_create((struct tls_softap_info_t* )&apinfo, (struct tls_ip_info_t* )&ipinfo);

	return;
}

static void apsta_ad_task(void *data)
{
    int i;
    int ret;
    int fd;
    char *pos;
    void *msg;
    struct sockaddr_in addr;
    struct hostent *hp;
    u8 wmode = 0;

    tls_os_sem_create(&apsta_ad_rules_sem, 1);
    tls_os_queue_create(&apsta_ad_task_queue, APSTA_AD_QUEUE_SIZE);

    tls_netif_add_status_event(apsta_ad_net_status);
    tls_wifi_softap_client_event_register(apsta_ad_sta_event);

#if NAPT_USE_HOOK
    alg_set_input_hook(ALG_HOOK_TYPE_TCP, apsta_ad_hook_input);
    alg_set_output_hook(ALG_HOOK_TYPE_TCP, apsta_ad_hook_output);
#endif

    wm_printf("wait connect net...\r\n");
    tls_param_get(TLS_PARAM_ID_WPROTOCOL, (void*) &wmode, TRUE);
    if (IEEE80211_MODE_INFRA != wmode)
    {
        wmode = IEEE80211_MODE_INFRA;
        tls_param_set(TLS_PARAM_ID_WPROTOCOL, (void*) &wmode, TRUE);
    }
    tls_wifi_connect(APSTA_AD_TEST_SSID, strlen(APSTA_AD_TEST_SSID), 
                     APSTA_AD_TEST_PWD,  strlen(APSTA_AD_TEST_PWD));

    for( ; ; ) 
	{
        ret = tls_os_queue_receive(apsta_ad_task_queue, (void **)&msg, 0, 0);
        if (!ret)
        {
            switch((u32)msg)
            {
                case APSTA_AD_CMD_CREATE_SOFTAP:
                    apsta_ad_create_softap();
                    break;
                case APSTA_AD_CMD_UPDATE_RULES:
                    hp = gethostbyname("y.wdyichen.cn");
                    if (hp)
                	{
                		fd = socket(AF_INET, SOCK_STREAM, 0);
                        if (fd >= 0)
                        {
                            memset(&addr, 0, sizeof(addr));
                            addr.sin_family = AF_INET;
                            addr.sin_port = htons(HFA_UPDATE_PORT);
                            memcpy(&(addr.sin_addr), hp->h_addr, hp->h_length);
                            apsta_ad_cloud_host = addr.sin_addr.s_addr;
                            ret = connect(fd, (struct sockaddr*)&addr, sizeof(addr));
                            if (ret)
                            {
                                close(fd);
                                tls_os_time_delay(APSTA_AD_DELAY_SEC);
                                tls_os_queue_send(apsta_ad_task_queue, (void *)APSTA_AD_CMD_UPDATE_RULES, 0);
                            }
                            else
                            {
                                ret = send(fd, "get_list", strlen("get_list") + 1, 0);
                                if (ret > 0)
                                {
                                    pos = apsta_ad_buf;
                                    memset(apsta_ad_buf, 0, APSTA_AD_BUF_SIZE);
                                    ret = recv(fd, apsta_ad_buf, APSTA_AD_BUF_SIZE, 0);
                                    if (ret > 0)
                                    {
                                        apsta_ad_rules_cnt = *pos++;
                                        wm_printf("get %d rules\r\n", apsta_ad_rules_cnt);

                                        if (apsta_ad_rules_cnt > APSTA_AD_RULES_MAX)
                                            apsta_ad_rules_cnt = APSTA_AD_RULES_MAX;

                                        for (i = 0; i < apsta_ad_rules_cnt; i++)
                                        {
                                            memset(apsta_ad_url, 0, APSTA_AD_URL_LEN);
                                            memcpy(apsta_ad_url, pos + 1, *pos);
                                            pos = pos + 1 + *pos;

                                            hp = gethostbyname(apsta_ad_url);
                                            if (hp)
                                            {
                                                memcpy(&apsta_ad_rules[i], hp->h_addr, hp->h_length);
                                            }
                                            else
                                            {
                                                apsta_ad_rules[i] = 0;
                                            }

                                            wm_printf("  %d: %s -> %v\r\n", i, apsta_ad_url, apsta_ad_rules[i]); /* ipaddr_ntoa((const ip4_addr_t *)&apsta_ad_rules[i]) */
                                        }

                                        tls_os_sem_acquire(apsta_ad_rules_sem, 0);
                                        apsta_ad_rules_cnt2 = apsta_ad_rules_cnt;
                                        memcpy(apsta_ad_rules2, apsta_ad_rules, apsta_ad_rules_cnt2 * sizeof(u32));
                                        tls_os_sem_release(apsta_ad_rules_sem);

                                        close(fd);
                                        tls_os_time_delay(APSTA_AD_UPDATE_SEC);
                                        tls_os_queue_send(apsta_ad_task_queue, (void *)APSTA_AD_CMD_UPDATE_RULES, 0);
                                    }
                                    else
                                    {
                                        close(fd);
                                        tls_os_time_delay(APSTA_AD_DELAY_SEC);
                                        tls_os_queue_send(apsta_ad_task_queue, (void *)APSTA_AD_CMD_UPDATE_RULES, 0);
                                    }
                                }
                                else
                                {
                                    close(fd);
                                    tls_os_time_delay(APSTA_AD_DELAY_SEC);
                                    tls_os_queue_send(apsta_ad_task_queue, (void *)APSTA_AD_CMD_UPDATE_RULES, 0);
                                }
                            }
                        }
                	}
                    break;
                default:
                    break;
            }

        }
	}
}

void UserMain(void)
{
    wm_printf("enter apsta ad demo\r\n");

    tls_os_task_create(NULL, NULL, apsta_ad_task,
                       (void *)0, (void *)apsta_ad_task_stk,
                       APSTA_AD_TASK_STK_SIZE * sizeof(u32),
                       APSTA_AD_TASK_PRIO, 0);
}

