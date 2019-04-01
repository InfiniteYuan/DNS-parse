/* HTTPS GET Example using plain mbedTLS sockets
 *
 * Contacts the howsmyssl.com API via TLS v1.2 and reads a JSON
 * response.
 *
 * Adapted from the ssl_client1 example in mbedtls.
 *
 * Original Copyright (C) 2006-2016, ARM Limited, All Rights Reserved, Apache 2.0 License.
 * Additions Copyright (C) Copyright 2015-2016 Espressif Systems (Shanghai) PTE LTD, Apache 2.0 License.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event_loop.h"
#include "esp_log.h"
#include "esp_system.h"
#include "nvs_flash.h"

#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"

#include "mbedtls/platform.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"


// #define DNS_SVR "211.68.71.4"
// #define DNS_SVR "114.114.115.115"
#define DNS_SVR "114.114.114.114"
 
#define DNS_HOST  0x01
#define DNS_CNAME 0x05
 
int socketfd;
struct sockaddr_in dest;
 
static void  send_dns_request(const char *dns_name, bool isCNAME);
 
static void parse_dns_response();
 
/**
 * Generate DNS question chunk
 */
static void generate_question(const char *dns_name
		, unsigned char *buf , int *len);
 
/**
 * Check whether the current byte is 
 * a dns pointer or a length
 */
static int is_pointer(int in);
 
/**
 * Parse data chunk into dns name
 * @param chunk The complete response chunk
 * @param ptr The pointer points to data
 * @param out This will be filled with dns name
 * @param len This will be filled with the length of dns name
 */
static void parse_dns_name(unsigned char *chunk , unsigned char *ptr
		, char *out , int *len);

/* The examples use simple WiFi configuration that you can set via
   'make menuconfig'.

   If you'd rather not, just change the below entries to strings with
   the config you want - ie #define EXAMPLE_WIFI_SSID "mywifissid"
*/
#define EXAMPLE_WIFI_SSID "esp-liyin"
#define EXAMPLE_WIFI_PASS "espressif"

/* FreeRTOS event group to signal when we are connected & ready to make a request */
static EventGroupHandle_t wifi_event_group;

/* The event group allows multiple bits for each event,
   but we only care about one event - are we connected
   to the AP with an IP? */
const int CONNECTED_BIT = BIT0;
const int GET_CNAME_BIT = BIT1;

/* Constants that aren't configurable in menuconfig */
#define WEB_TEST_SERVER "cmd-eu-prod.worxlandroid.com"
#define WEB_SERVER "iot.infiniteyuan.com" // map to "www.howsmyssl.com"
#define WEB_PORT "443"
#define WEB_URL "https://iot.infiniteyuan.com/a/check"

static const char *TAG = "example";

static const char *REQUEST = "GET " WEB_URL " HTTP/1.0\r\n"
    "Host: "WEB_SERVER"\r\n"
    "User-Agent: esp-idf/1.0 esp32\r\n"
    "\r\n";

/* Root cert for howsmyssl.com, taken from server_root_cert.pem

   The PEM file was extracted from the output of this command:
   openssl s_client -showcerts -connect www.howsmyssl.com:443 </dev/null

   The CA root cert is the last cert given in the chain of certs.

   To embed it in the app binary, the PEM file is named
   in the component.mk COMPONENT_EMBED_TXTFILES variable.
*/
extern const uint8_t server_root_cert_pem_start[] asm("_binary_server_root_cert_pem_start");
extern const uint8_t server_root_cert_pem_end[]   asm("_binary_server_root_cert_pem_end");

#define DNS_QUERY_EXAMPLE_TASK_NAME        "dns_query_example"
#define DNS_QUERY_EXAMPLE_TASK_STACK_WORDS 1024 * 12
#define DNS_QUERY_EXAMPLE_TASK_PRIORITY    8

static char find_cname[128] = {0};

static void dns_query_example_task(void *p)
{
    int ret;
    int sockfd;
    struct sockaddr_in sock_addr;
    struct hostent *hp;
    struct ip4_addr *ip4_addr;

    /* Wait for the callback to set the CONNECTED_BIT in the
        event group.
    */
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
                        false, true, portMAX_DELAY);

	socketfd = socket(AF_INET , SOCK_DGRAM , 0);
	if(socketfd < 0){
		perror("create socket failed");
		exit(-1);
	}
	bzero(&dest , sizeof(dest));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);
	dest.sin_addr.s_addr = inet_addr(DNS_SVR);
 
    printf("dnslook for %s\n", WEB_SERVER);
	send_dns_request(WEB_SERVER, true);
 
	parse_dns_response();

    xEventGroupSetBits(wifi_event_group, GET_CNAME_BIT);

    printf("dnslook for %s\n", WEB_TEST_SERVER);
	send_dns_request(WEB_TEST_SERVER, true);
 
	parse_dns_response();
    
    vTaskDelay(3000/portTICK_PERIOD_MS);
    vTaskDelete(NULL);
}

static void dns_query_example_init(void)
{
    int ret;
    xTaskHandle openssl_handle;

    ESP_LOGI(TAG, "dns_query_example_init");

    ret = xTaskCreate(dns_query_example_task,
                      DNS_QUERY_EXAMPLE_TASK_NAME,
                      DNS_QUERY_EXAMPLE_TASK_STACK_WORDS,
                      NULL,
                      DNS_QUERY_EXAMPLE_TASK_PRIORITY,
                      &openssl_handle);

    if (ret != pdPASS)  {
        ESP_LOGI(TAG, "create thread %s failed", DNS_QUERY_EXAMPLE_TASK_NAME);
    }
}

static esp_err_t event_handler(void *ctx, system_event_t *event)
{
    switch(event->event_id) {
    case SYSTEM_EVENT_STA_START:
        esp_wifi_connect();
        break;
    case SYSTEM_EVENT_STA_GOT_IP:
        xEventGroupSetBits(wifi_event_group, CONNECTED_BIT);
        break;
    case SYSTEM_EVENT_STA_DISCONNECTED:
        /* This is a workaround as ESP32 WiFi libs don't currently
           auto-reassociate. */
        esp_wifi_connect();
        xEventGroupClearBits(wifi_event_group, CONNECTED_BIT);
        break;
    default:
        break;
    }
    return ESP_OK;
}

static void initialise_wifi(void)
{
    tcpip_adapter_init();
    wifi_event_group = xEventGroupCreate();
    ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
    wifi_config_t wifi_config = {
        .sta = {
            .ssid = EXAMPLE_WIFI_SSID,
            .password = EXAMPLE_WIFI_PASS,
        },
    };
    ESP_LOGI(TAG, "Setting WiFi configuration SSID %s...", wifi_config.sta.ssid);
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_set_config(ESP_IF_WIFI_STA, &wifi_config) );
    ESP_ERROR_CHECK( esp_wifi_start() );
}

static void https_get_task(void *pvParameters)
{
    char buf[512];
    int ret, flags, len;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_x509_crt cacert;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;

    mbedtls_ssl_init(&ssl);
    mbedtls_x509_crt_init(&cacert);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    ESP_LOGI(TAG, "Seeding the random number generator");

    mbedtls_ssl_config_init(&conf);

    mbedtls_entropy_init(&entropy);
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    NULL, 0)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ctr_drbg_seed returned %d", ret);
        abort();
    }

    ESP_LOGI(TAG, "Loading the CA root certificate...");

    ret = mbedtls_x509_crt_parse(&cacert, server_root_cert_pem_start,
                                 server_root_cert_pem_end-server_root_cert_pem_start);

    if(ret < 0)
    {
        ESP_LOGE(TAG, "mbedtls_x509_crt_parse returned -0x%x\n\n", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting hostname for TLS session...");

    /* Wait for the callback to set the CONNECTED_BIT|GET_CNAME_BIT in the
        event group.
    */
    xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT|GET_CNAME_BIT,
                        false, true, portMAX_DELAY);

	printf("find_cname %s\n" , find_cname);
     /* Hostname set here should match CN in server certificate */
    if((ret = mbedtls_ssl_set_hostname(&ssl, find_cname)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_set_hostname returned -0x%x", -ret);
        abort();
    }

    ESP_LOGI(TAG, "Setting up the SSL/TLS structure...");

    if((ret = mbedtls_ssl_config_defaults(&conf,
                                          MBEDTLS_SSL_IS_CLIENT,
                                          MBEDTLS_SSL_TRANSPORT_STREAM,
                                          MBEDTLS_SSL_PRESET_DEFAULT)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_config_defaults returned %d", ret);
        goto exit;
    }

    /* MBEDTLS_SSL_VERIFY_OPTIONAL is bad for security, in this example it will print
       a warning if CA verification fails but it will continue to connect.

       You should consider using MBEDTLS_SSL_VERIFY_REQUIRED in your own code.
    */
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&conf, &cacert, NULL);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
#ifdef CONFIG_MBEDTLS_DEBUG
    mbedtls_esp_enable_debug_log(&conf, 4);
#endif

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0)
    {
        ESP_LOGE(TAG, "mbedtls_ssl_setup returned -0x%x\n\n", -ret);
        goto exit;
    }

    while(1) {
        ESP_LOGI(TAG, "Connected to AP");

        mbedtls_net_init(&server_fd);

        ESP_LOGI(TAG, "Connecting to %s:%s...", WEB_SERVER, WEB_PORT);

        if ((ret = mbedtls_net_connect(&server_fd, WEB_SERVER,
                                      WEB_PORT, MBEDTLS_NET_PROTO_TCP)) != 0)
        {
            ESP_LOGE(TAG, "mbedtls_net_connect returned -%x", -ret);
            goto exit;
        }

        ESP_LOGI(TAG, "Connected.");

        mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

        ESP_LOGI(TAG, "Performing the SSL/TLS handshake...");

        while ((ret = mbedtls_ssl_handshake(&ssl)) != 0)
        {
            if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_handshake returned -0x%x", -ret);
                goto exit;
            }
        }

        ESP_LOGI(TAG, "Verifying peer X.509 certificate...");

        if ((flags = mbedtls_ssl_get_verify_result(&ssl)) != 0)
        {
            /* In real life, we probably want to close connection if ret != 0 */
            ESP_LOGW(TAG, "Failed to verify peer certificate!");
            bzero(buf, sizeof(buf));
            mbedtls_x509_crt_verify_info(buf, sizeof(buf), "  ! ", flags);
            ESP_LOGW(TAG, "verification info: %s", buf);
        }
        else {
            ESP_LOGI(TAG, "Certificate verified.");
        }

        ESP_LOGI(TAG, "Cipher suite is %s", mbedtls_ssl_get_ciphersuite(&ssl));

        ESP_LOGI(TAG, "Writing HTTP request...");

        size_t written_bytes = 0;
        do {
            ret = mbedtls_ssl_write(&ssl,
                                    (const unsigned char *)REQUEST + written_bytes,
                                    strlen(REQUEST) - written_bytes);
            if (ret >= 0) {
                ESP_LOGI(TAG, "%d bytes written", ret);
                written_bytes += ret;
            } else if (ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_WANT_READ) {
                ESP_LOGE(TAG, "mbedtls_ssl_write returned -0x%x", -ret);
                goto exit;
            }
        } while(written_bytes < strlen(REQUEST));

        ESP_LOGI(TAG, "Reading HTTP response...");

        do
        {
            len = sizeof(buf) - 1;
            bzero(buf, sizeof(buf));
            ret = mbedtls_ssl_read(&ssl, (unsigned char *)buf, len);

            if(ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE)
                continue;

            if(ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                ret = 0;
                break;
            }

            if(ret < 0)
            {
                ESP_LOGE(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
                break;
            }

            if(ret == 0)
            {
                ESP_LOGI(TAG, "connection closed");
                break;
            }

            len = ret;
            ESP_LOGD(TAG, "%d bytes read", len);
            /* Print response directly to stdout as it is read */
            for(int i = 0; i < len; i++) {
                putchar(buf[i]);
            }
        } while(1);

        mbedtls_ssl_close_notify(&ssl);

    exit:
        mbedtls_ssl_session_reset(&ssl);
        mbedtls_net_free(&server_fd);

        if(ret != 0)
        {
            mbedtls_strerror(ret, buf, 100);
            ESP_LOGE(TAG, "Last error was: -0x%x - %s", -ret, buf);
        }

        putchar('\n'); // JSON output doesn't have a newline at end

        static int request_count;
        ESP_LOGI(TAG, "Completed %d requests", ++request_count);

        for(int countdown = 10; countdown >= 0; countdown--) {
            ESP_LOGI(TAG, "%d...", countdown);
            vTaskDelay(1000 / portTICK_PERIOD_MS);
        }
        ESP_LOGI(TAG, "Starting again!");
    }
}

void app_main()
{
    ESP_ERROR_CHECK( nvs_flash_init() );
    initialise_wifi();
    dns_query_example_init();
    xTaskCreate(&https_get_task, "https_get_task", 8192, NULL, 5, NULL);
}

#define DNS_DEBUG 0

static void parse_dns_response(){
 
	unsigned char buf[1024];
	unsigned char *ptr = buf;
	struct sockaddr_in addr;
	char *src_ip;
	int n , i , flag , querys , answers;
	int type , ttl , datalen , len;
	char cname[128] , aname[128] , ip[20] , *cname_ptr;
	unsigned char netip[4];
    static bool is_find_cname = false;
	size_t addr_len = sizeof(struct sockaddr_in);
 
	n = recvfrom(socketfd , buf , sizeof(buf) , 0
		, (struct sockaddr*)&addr , &addr_len);
#if DNS_DEBUG
	printf("-------------------------------\n");
    for (int cou = 0; cou < n ; cou++) {
        if(cou % 16 == 0)
            printf("\n");
        printf("%02x ", buf[cou]);
    }
    printf("\n\nresponse length:%d\n\n", n);
#endif
	ptr += 4; /* move ptr to Questions */
	querys = ntohs(*((unsigned short*)ptr));
	ptr += 2; /* move ptr to Answer RRs */
	answers = ntohs(*((unsigned short*)ptr));
	ptr += 6; /* move ptr to Querys */
	/* move over Querys */
	for(i= 0 ; i < querys ; i ++){
		for(;;){
			flag = (int)ptr[0];
			ptr += (flag + 1);
			if(flag == 0)
				break;
		}
		ptr += 4;
	}
	/* now ptr points to Answers */
	for(i = 0 ; i < answers ; i ++){
        vTaskDelay(10/portTICK_PERIOD_MS);
		bzero(aname , sizeof(aname));
		len = 0;
		parse_dns_name(buf , ptr , aname , &len);
		ptr += 2; /* move ptr to Type*/
		type = htons(*((unsigned short*)ptr));
		ptr += 4; /* move ptr to Time to live */
		ttl = htonl(*((unsigned int*)ptr));
		ptr += 4; /* move ptr to Data lenth */
		datalen = ntohs(*((unsigned short*)ptr));
		ptr += 2; /* move ptr to Data*/
		if(type == DNS_CNAME){
			bzero(cname , sizeof(cname));
			len = 0;
			parse_dns_name(buf , ptr , cname , &len);
            if(is_find_cname == false) {
                strcpy(find_cname, cname);
            }
            is_find_cname = true;
			printf("%s is an alias for %s\n" , aname , cname);
			ptr += datalen;
		}
		if(type == DNS_HOST){
			bzero(ip , sizeof(ip));
			if(datalen == 4){
				memcpy(netip , ptr , datalen);
				inet_ntop(AF_INET , netip , ip , sizeof(struct sockaddr));
				printf("%s has address %s\n" , aname , ip);
				printf("\tTime to live: %d minutes , %d seconds\n"
						, ttl / 60 , ttl % 60);
			}
			ptr += datalen;
		}
 
	}
	ptr += 2;
}
 
static void parse_dns_name(unsigned char *chunk
		, unsigned char *ptr , char *out , int *len){
	int n , alen , flag;
	char *pos = out + (*len);
 
	for(;;){
        vTaskDelay(10/portTICK_PERIOD_MS);
		flag = (int)ptr[0];
		if(flag == 0)
			break;
		if(is_pointer(flag)){
			n = (int)ptr[1];
			ptr = chunk + n;
			parse_dns_name(chunk , ptr , out , len);
			break;
		}else{
			ptr ++;
			memcpy(pos , ptr , flag);	
			pos += flag;
			ptr += flag;
			*len += flag;
			if((int)ptr[0] != 0){
				memcpy(pos , "." , 1);
				pos += 1;
				(*len) += 1;
			}
		}
	}
 
}
 
static int is_pointer(int in){
	return ((in & 0xc0) == 0xc0);
}
 
static void send_dns_request(const char *dns_name, bool isCNAME){
 
	unsigned char request[256];
	unsigned char *ptr = request;
	unsigned char question[128];
	int question_len;
 
    vTaskDelay(30/portTICK_PERIOD_MS);
 
	generate_question(dns_name , question , &question_len);
 
	*((unsigned short*)ptr) = htons(0xff00);
	ptr += 2;
	*((unsigned short*)ptr) = htons(0x0100);
	ptr += 2;
	*((unsigned short*)ptr) = htons(1);
	ptr += 2;
	*((unsigned short*)ptr) = 0;
	ptr += 2;
	*((unsigned short*)ptr) = 0;
	ptr += 2;
	*((unsigned short*)ptr) = 0;
	ptr += 2;
	memcpy(ptr , question , question_len);
	ptr += question_len;
    
    if(isCNAME) {
        request[question_len + 10 - 1] = 0x02;
    }

	sendto(socketfd , request , question_len + 12 , 0
	   , (struct sockaddr*)&dest , sizeof(struct sockaddr));

#if DNS_DEBUG
    for (int cou = 0; cou < (question_len + 12) ; cou++) {
        if(cou % 16 == 0)
            printf("\n");
        printf("%02x ", request[cou]);
    }
    printf("\n\nquery length:%d\n\n", question_len + 12);
#endif
}
 
static void generate_question(const char *dns_name , unsigned char *buf , int *len){
	char *pos;
	unsigned char *ptr;
	int n;
 
	*len = 0;
	ptr = buf;	
	pos = (char*)dns_name; 
	for(;;){
		n = strlen(pos) - (strstr(pos , ".") ? strlen(strstr(pos , ".")) : 0);
		*ptr ++ = (unsigned char)n;
		memcpy(ptr , pos , n);
		*len += n + 1;
		ptr += n;
        vTaskDelay(10/portTICK_PERIOD_MS);
		if(!strstr(pos , ".")){
			*ptr = (unsigned char)0;
			ptr ++;
			*len += 1;
			break;
		}
		pos += n + 1;
	}
	*((unsigned short*)ptr) = htons(1);
	*len += 2;
	ptr += 2;
	*((unsigned short*)ptr) = htons(1);
	*len += 2;
}
