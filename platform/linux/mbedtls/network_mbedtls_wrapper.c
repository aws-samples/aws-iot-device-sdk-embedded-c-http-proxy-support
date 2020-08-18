/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License.
 * A copy of the License is located at
 *
 *  http://aws.amazon.com/apache2.0
 *
 * or in the "license" file accompanying this file. This file is distributed
 * on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
 * express or implied. See the License for the specific language governing
 * permissions and limitations under the License.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <string.h>
#include <timer_platform.h>
#include <network_interface.h>

#include "aws_iot_error.h"
#include "aws_iot_log.h"
#include "network_interface.h"
#include "network_platform.h"


/* This is the value used for ssl read timeout */
#define IOT_SSL_READ_TIMEOUT 10

/* This defines the value of the debug buffer that gets allocated.
 * The value can be altered based on memory constraints
 */
#ifdef ENABLE_IOT_DEBUG
#define MBEDTLS_DEBUG_BUFFER_SIZE 2048
#endif

/* This is the length of the HTTP Connect request without the Proxy-Authorization header and host:port values, excluding terminating null char */
#define HTTP_CONNECT_REQUEST_BASE_LEN 62

/* This is the length of the HTTP Connect request Proxy-Authorization header, without the base64 encoded credentials, excluding terminating null char */
#define HTTP_CONNECT_AUTH_HEADER_BASE_LEN 29

/* This is the length limit of the HTTP proxy credentials <username>:<password>, including the colon, excluding terminating null char */
#define HTTP_PROXY_CREDENTIALS_LEN_LIMIT 64

/* This is the length of the base64 encoded HTTP proxy credentials <username>:<password>, excluding terminating null char */
#define HTTP_PROXY_ENCODED_CREDENTIALS_LEN (HTTP_PROXY_CREDENTIALS_LEN_LIMIT + 2) / 3 * 4

/* This is max length of the AWS IoT endpoint host, excluding terminating null char */
#define AWS_IOT_MQTT_HOST_LEN_MAX 60
/* This is max length of the AWS IoT endpoint port, excluding terminating null char */
#define AWS_IOT_MQTT_PORT_LEN_MAX 5

/* This is the max length of the HTTP Connect request buffer, with an extra space for null terminating char */
#define HTTP_CONNECT_REQUEST_BUF_LEN_MAX HTTP_CONNECT_REQUEST_BASE_LEN + HTTP_CONNECT_AUTH_HEADER_BASE_LEN \
										 + 2 * (AWS_IOT_MQTT_HOST_LEN_MAX + AWS_IOT_MQTT_PORT_LEN_MAX) \
										 + HTTP_PROXY_ENCODED_CREDENTIALS_LEN + 1

/* This is the buffer position offset of the raw credentials that is temporarily stored in the request buffer */
#define RAW_CREDENTIALS_OFFSET HTTP_CONNECT_REQUEST_BUF_LEN_MAX - HTTP_PROXY_CREDENTIALS_LEN_LIMIT - 1

/*
 * This is a function to do further verification if needed on the cert received
 */

static int _iot_tls_verify_cert(void *data, mbedtls_x509_crt *crt, int depth, uint32_t *flags) {
	char buf[1024];
	((void) data);

	IOT_DEBUG("\nVerify requested for (Depth %d):\n", depth);
	mbedtls_x509_crt_info(buf, sizeof(buf) - 1, "", crt);
	IOT_DEBUG("%s", buf);

	if((*flags) == 0) {
		IOT_DEBUG("  This certificate has no flags\n");
	} else {
		IOT_DEBUG(buf, sizeof(buf), "  ! ", *flags);
		IOT_DEBUG("%s\n", buf);
	}

	return 0;
}

void _iot_tls_set_connect_params(Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
								 char *pDevicePrivateKeyLocation, char *pDestinationURL,
								 uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag) {
	pNetwork->tlsConnectParams.DestinationPort = destinationPort;
	pNetwork->tlsConnectParams.pDestinationURL = pDestinationURL;
	pNetwork->tlsConnectParams.pDeviceCertLocation = pDeviceCertLocation;
	pNetwork->tlsConnectParams.pDevicePrivateKeyLocation = pDevicePrivateKeyLocation;
	pNetwork->tlsConnectParams.pRootCALocation = pRootCALocation;
	pNetwork->tlsConnectParams.timeout_ms = timeout_ms;
	pNetwork->tlsConnectParams.ServerVerificationFlag = ServerVerificationFlag;
}

IoT_Error_t iot_tls_init(Network *pNetwork, char *pRootCALocation, char *pDeviceCertLocation,
						 char *pDevicePrivateKeyLocation, char *pDestinationURL,
						 uint16_t destinationPort, uint32_t timeout_ms, bool ServerVerificationFlag) {
	_iot_tls_set_connect_params(pNetwork, pRootCALocation, pDeviceCertLocation, pDevicePrivateKeyLocation,
								pDestinationURL, destinationPort, timeout_ms, ServerVerificationFlag);

	pNetwork->connect = iot_tls_connect;
	pNetwork->read = iot_tls_read;
	pNetwork->write = iot_tls_write;
	pNetwork->disconnect = iot_tls_disconnect;
	pNetwork->isConnected = iot_tls_is_connected;
	pNetwork->destroy = iot_tls_destroy;

	pNetwork->tlsDataParams.flags = 0;

	return SUCCESS;
}

IoT_Error_t iot_proxy_init(Network *pNetwork, Proxy_Type_t ProxyType, char *pProxyHostURL,
						 uint16_t ProxyPort, bool AuthenticationRequiredFlag,
						 char *pProxyUserName, char *pProxyPassword) {
	if (ProxyType == PROXY_DISABLED) {
		return SUCCESS;
	}

	IOT_DEBUG("  . Proxy configurations init ...");

	pNetwork->proxyParams.proxyType = ProxyType;
	pNetwork->proxyParams.pProxyHostURL = pProxyHostURL;
	pNetwork->proxyParams.proxyPort = ProxyPort;
	pNetwork->proxyParams.isAuthenticationRequired = AuthenticationRequiredFlag;
	pNetwork->proxyParams.pProxyUserName = pProxyUserName;
	pNetwork->proxyParams.pProxyPassword = pProxyPassword;

	return SUCCESS;
}

IoT_Error_t iot_tls_is_connected(Network *pNetwork) {
	/* Use this to add implementation which can check for physical layer disconnect */
	return NETWORK_PHYSICAL_LAYER_CONNECTED;
}

static IoT_Error_t _iot_http_proxy_connect(Network *pNetwork, char *pRemoteHost, uint16_t remotePort) {
	int ret = -1;
	int statusCode = -1;
	size_t offset = 0;
	size_t credentialsSize = 0;
	size_t olen = 0;
	unsigned char buffer[HTTP_CONNECT_REQUEST_BUF_LEN_MAX];

	// Build HTTP CONNECT request
	offset += snprintf(buffer, sizeof(buffer),
				"CONNECT %s:%d HTTP/1.1\r\n"
				"Host: %s:%d\r\n"
				"Proxy-Connection: Keep-Alive\r\n",
				pRemoteHost, remotePort,
				pRemoteHost, remotePort);

	// Build Authorization Header if required
	if(pNetwork->proxyParams.isAuthenticationRequired) {
		offset += snprintf(buffer + offset, sizeof(buffer) - offset, "Proxy-Authorization: Basic ");

		if(HTTP_PROXY_CREDENTIALS_LEN_LIMIT < strlen(pNetwork->proxyParams.pProxyUserName) \
			 + strlen(pNetwork->proxyParams.pProxyPassword) + 1) {
			IOT_ERROR(" failed! proxy credentials are too long: <user:pass> limit %d \n\n", HTTP_PROXY_CREDENTIALS_LEN_LIMIT);
			return NETWORK_ERR_NET_CONNECT_FAILED;
		}

		credentialsSize = snprintf(buffer + RAW_CREDENTIALS_OFFSET,  HTTP_PROXY_CREDENTIALS_LEN_LIMIT + 1, "%s:%s",
			pNetwork->proxyParams.pProxyUserName,
			pNetwork->proxyParams.pProxyPassword
		);

		if((ret = mbedtls_base64_encode(buffer + offset, sizeof(buffer) - offset, &olen, \
				buffer + RAW_CREDENTIALS_OFFSET, credentialsSize)) != 0) {
			IOT_ERROR(" failed to base64_encode proxy credentials -0x%x\n\n", -ret);
			return ret;
		}
		offset += olen;
		offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\r\n");
	}
	offset += snprintf(buffer + offset, sizeof(buffer) - offset, "\r\n");

	buffer[offset] = '\0';
	IOT_DEBUG("HTTP Connect Request:");
	IOT_DEBUG(buffer);

	// Send HTTP CONNECT request
	ret = mbedtls_net_send(&(pNetwork->tlsDataParams.server_fd), buffer, offset);
	IOT_DEBUG("send HTTP request %d\n", ret);
	if(ret < 0) {
		IOT_ERROR(" failed\n  !  send returned -0x%x\n\n", -ret);
		return NETWORK_ERR_NET_CONNECT_FAILED;
	}
	IOT_DEBUG(" ok\n");

	// Receive HTTP response
	memset(buffer, 0, sizeof(buffer));
	ret = mbedtls_net_recv(&(pNetwork->tlsDataParams.server_fd), buffer, sizeof(buffer));
	IOT_DEBUG("receive HTTP response %d\n", ret);
	buffer[ret] = '\0';

	IOT_DEBUG(buffer);
	if(ret < 0) {
		IOT_ERROR(" failed\n  !  recv returned -0x%x\n\n", -ret);
		return NETWORK_ERR_NET_CONNECT_FAILED;
	}
	IOT_DEBUG(" ok\n");

	// Extract status code
	ret = sscanf(buffer, "HTTP/%*s %d", &statusCode);
	if(ret != 1) {
		IOT_ERROR(" failed\n  !  mal-formed response from HTTP proxy \n\n");
		return NETWORK_ERR_NET_CONNECT_FAILED;
	}

	if (statusCode >= 400 || statusCode < 200) {
		IOT_ERROR(" failed\n  !  invalid HTTP response from proxy server %d\n\n", statusCode);
		return NETWORK_ERR_NET_CONNECT_FAILED;
	}

	return SUCCESS;
}

IoT_Error_t iot_tls_connect(Network *pNetwork, TLSConnectParams *params) {
	int ret = 0;
	const char *pers = "aws_iot_tls_wrapper";
	TLSDataParams *tlsDataParams = NULL;
	char portBuffer[6];
	char vrfy_buf[512];
	const char *alpnProtocols[] = { "x-amzn-mqtt-ca", NULL };
	const char *pHost = pNetwork->tlsConnectParams.pDestinationURL;

#ifdef ENABLE_IOT_DEBUG
	static unsigned char buf[MBEDTLS_DEBUG_BUFFER_SIZE];
#endif

	if(NULL == pNetwork) {
		return NULL_VALUE_ERROR;
	}

	if(NULL != params) {
		_iot_tls_set_connect_params(pNetwork, params->pRootCALocation, params->pDeviceCertLocation,
									params->pDevicePrivateKeyLocation, params->pDestinationURL,
									params->DestinationPort, params->timeout_ms, params->ServerVerificationFlag);
	}

	tlsDataParams = &(pNetwork->tlsDataParams);

	mbedtls_net_init(&(tlsDataParams->server_fd));
	mbedtls_ssl_init(&(tlsDataParams->ssl));
	mbedtls_ssl_config_init(&(tlsDataParams->conf));
	mbedtls_ctr_drbg_init(&(tlsDataParams->ctr_drbg));
	mbedtls_x509_crt_init(&(tlsDataParams->cacert));
	mbedtls_x509_crt_init(&(tlsDataParams->clicert));
	mbedtls_pk_init(&(tlsDataParams->pkey));

	IOT_DEBUG("\n  . Seeding the random number generator...");
	mbedtls_entropy_init(&(tlsDataParams->entropy));
	if((ret = mbedtls_ctr_drbg_seed(&(tlsDataParams->ctr_drbg), mbedtls_entropy_func, &(tlsDataParams->entropy),
									(const unsigned char *) pers, strlen(pers))) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_ctr_drbg_seed returned -0x%x\n", -ret);
		return NETWORK_MBEDTLS_ERR_CTR_DRBG_ENTROPY_SOURCE_FAILED;
	}

	IOT_DEBUG("  . Loading the CA root certificate ...");
	ret = mbedtls_x509_crt_parse_file(&(tlsDataParams->cacert), pNetwork->tlsConnectParams.pRootCALocation);
	if(ret < 0) {
		IOT_ERROR(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing root cert\n\n", -ret);
		return NETWORK_X509_ROOT_CRT_PARSE_ERROR;
	}
	IOT_DEBUG(" ok (%d skipped)\n", ret);

	IOT_DEBUG("  . Loading the client cert. and key...");
	ret = mbedtls_x509_crt_parse_file(&(tlsDataParams->clicert), pNetwork->tlsConnectParams.pDeviceCertLocation);
	if(ret != 0) {
		IOT_ERROR(" failed\n  !  mbedtls_x509_crt_parse returned -0x%x while parsing device cert\n\n", -ret);
		return NETWORK_X509_DEVICE_CRT_PARSE_ERROR;
	}

	ret = mbedtls_pk_parse_keyfile(&(tlsDataParams->pkey), pNetwork->tlsConnectParams.pDevicePrivateKeyLocation, "");
	if(ret != 0) {
		IOT_ERROR(" failed\n  !  mbedtls_pk_parse_key returned -0x%x while parsing private key\n\n", -ret);
		IOT_DEBUG(" path : %s ", pNetwork->tlsConnectParams.pDevicePrivateKeyLocation);
		return NETWORK_PK_PRIVATE_KEY_PARSE_ERROR;
	}
	IOT_DEBUG(" ok\n");
	snprintf(portBuffer, 6, "%d", pNetwork->tlsConnectParams.DestinationPort);

	if(pNetwork->proxyParams.proxyType == PROXY_HTTP) {
		pHost = pNetwork->proxyParams.pProxyHostURL;
		snprintf(portBuffer, sizeof(portBuffer), "%d", pNetwork->proxyParams.proxyPort);
		IOT_DEBUG("  . Connecting to %s/%d via HTTP proxy %s/%s",
			pNetwork->tlsConnectParams.pDestinationURL, pNetwork->tlsConnectParams.DestinationPort,
			pHost, portBuffer
		);
	} else {
		IOT_DEBUG("  . Connecting to %s/%s...", pNetwork->tlsConnectParams.pDestinationURL, portBuffer);
	}

	if((ret = mbedtls_net_connect(&(tlsDataParams->server_fd), pHost, portBuffer, MBEDTLS_NET_PROTO_TCP)) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_net_connect returned -0x%x\n\n", -ret);
		switch(ret) {
			case MBEDTLS_ERR_NET_SOCKET_FAILED:
				return NETWORK_ERR_NET_SOCKET_FAILED;
			case MBEDTLS_ERR_NET_UNKNOWN_HOST:
				return NETWORK_ERR_NET_UNKNOWN_HOST;
			case MBEDTLS_ERR_NET_CONNECT_FAILED:
			default:
				return NETWORK_ERR_NET_CONNECT_FAILED;
		};
	}

	if(pNetwork->proxyParams.proxyType == PROXY_HTTP) {
		ret = _iot_http_proxy_connect(
			pNetwork,
			pNetwork->tlsConnectParams.pDestinationURL,
			pNetwork->tlsConnectParams.DestinationPort
		);
		if(ret != SUCCESS) {
			IOT_ERROR(" failed\n  ! cannot connect to HTTP proxy server\n\n");
			return NETWORK_ERR_NET_CONNECT_FAILED;
		}
	}

	ret = mbedtls_net_set_block(&(tlsDataParams->server_fd));
	if(ret != 0) {
		IOT_ERROR(" failed\n  ! net_set_(non)block() returned -0x%x\n\n", -ret);
		return SSL_CONNECTION_ERROR;
	} IOT_DEBUG(" ok\n");

	IOT_DEBUG("  . Setting up the SSL/TLS structure...");
	if((ret = mbedtls_ssl_config_defaults(&(tlsDataParams->conf), MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM,
										  MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_ssl_config_defaults returned -0x%x\n\n", -ret);
		return SSL_CONNECTION_ERROR;
	}

	mbedtls_ssl_conf_verify(&(tlsDataParams->conf), _iot_tls_verify_cert, NULL);
	if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
		mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_REQUIRED);
	} else {
		mbedtls_ssl_conf_authmode(&(tlsDataParams->conf), MBEDTLS_SSL_VERIFY_OPTIONAL);
	}
	mbedtls_ssl_conf_rng(&(tlsDataParams->conf), mbedtls_ctr_drbg_random, &(tlsDataParams->ctr_drbg));

	mbedtls_ssl_conf_ca_chain(&(tlsDataParams->conf), &(tlsDataParams->cacert), NULL);
	if((ret = mbedtls_ssl_conf_own_cert(&(tlsDataParams->conf), &(tlsDataParams->clicert), &(tlsDataParams->pkey))) !=
	   0) {
		IOT_ERROR(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
		return SSL_CONNECTION_ERROR;
	}

	mbedtls_ssl_conf_read_timeout(&(tlsDataParams->conf), pNetwork->tlsConnectParams.timeout_ms);

	/* Use the AWS IoT ALPN extension for MQTT if port 443 is requested. */
	if(443 == pNetwork->tlsConnectParams.DestinationPort) {
		if((ret = mbedtls_ssl_conf_alpn_protocols(&(tlsDataParams->conf), alpnProtocols)) != 0) {
			IOT_ERROR(" failed\n  ! mbedtls_ssl_conf_alpn_protocols returned -0x%x\n\n", -ret);
			return SSL_CONNECTION_ERROR;
		}
	}

	/* Assign the resulting configuration to the SSL context. */
	if((ret = mbedtls_ssl_setup(&(tlsDataParams->ssl), &(tlsDataParams->conf))) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_ssl_setup returned -0x%x\n\n", -ret);
		return SSL_CONNECTION_ERROR;
	}
	if((ret = mbedtls_ssl_set_hostname(&(tlsDataParams->ssl), pNetwork->tlsConnectParams.pDestinationURL)) != 0) {
		IOT_ERROR(" failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret);
		return SSL_CONNECTION_ERROR;
	}
	IOT_DEBUG("\n\nSSL state connect : %d ", tlsDataParams->ssl.state);
	mbedtls_ssl_set_bio(&(tlsDataParams->ssl), &(tlsDataParams->server_fd), mbedtls_net_send, NULL,
						mbedtls_net_recv_timeout);
	IOT_DEBUG(" ok\n");

	IOT_DEBUG("\n\nSSL state connect : %d ", tlsDataParams->ssl.state);
	IOT_DEBUG("  . Performing the SSL/TLS handshake...");
	while((ret = mbedtls_ssl_handshake(&(tlsDataParams->ssl))) != 0) {
		if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
			IOT_ERROR(" failed\n  ! mbedtls_ssl_handshake returned -0x%x\n", -ret);
			if(ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED) {
				IOT_ERROR("    Unable to verify the server's certificate. "
							  "Either it is invalid,\n"
							  "    or you didn't set ca_file or ca_path "
							  "to an appropriate value.\n"
							  "    Alternatively, you may want to use "
							  "auth_mode=optional for testing purposes.\n");
			}
			return SSL_CONNECTION_ERROR;
		}
	}

	IOT_DEBUG(" ok\n    [ Protocol is %s ]\n    [ Ciphersuite is %s ]\n", mbedtls_ssl_get_version(&(tlsDataParams->ssl)),
		  mbedtls_ssl_get_ciphersuite(&(tlsDataParams->ssl)));
	if((ret = mbedtls_ssl_get_record_expansion(&(tlsDataParams->ssl))) >= 0) {
		IOT_DEBUG("    [ Record expansion is %d ]\n", ret);
	} else {
		IOT_DEBUG("    [ Record expansion is unknown (compression) ]\n");
	}

	IOT_DEBUG("  . Verifying peer X.509 certificate...");

	if(pNetwork->tlsConnectParams.ServerVerificationFlag == true) {
		if((tlsDataParams->flags = mbedtls_ssl_get_verify_result(&(tlsDataParams->ssl))) != 0) {
			IOT_ERROR(" failed\n");
			mbedtls_x509_crt_verify_info(vrfy_buf, sizeof(vrfy_buf), "  ! ", tlsDataParams->flags);
			IOT_ERROR("%s\n", vrfy_buf);
			ret = SSL_CONNECTION_ERROR;
		} else {
			IOT_DEBUG(" ok\n");
			ret = SUCCESS;
		}
	} else {
		IOT_DEBUG(" Server Verification skipped\n");
		ret = SUCCESS;
	}

#ifdef ENABLE_IOT_DEBUG
	if (mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)) != NULL) {
		IOT_DEBUG("  . Peer certificate information    ...\n");
		mbedtls_x509_crt_info((char *) buf, sizeof(buf) - 1, "      ", mbedtls_ssl_get_peer_cert(&(tlsDataParams->ssl)));
		IOT_DEBUG("%s\n", buf);
	}
#endif

	mbedtls_ssl_conf_read_timeout(&(tlsDataParams->conf), IOT_SSL_READ_TIMEOUT);

	return (IoT_Error_t) ret;
}

IoT_Error_t iot_tls_write(Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer, size_t *written_len) {
	size_t written_so_far;
	bool isErrorFlag = false;
	int frags;
	int ret = 0;
	TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);

	for(written_so_far = 0, frags = 0;
		written_so_far < len && !has_timer_expired(timer); written_so_far += ret, frags++) {
		while(!has_timer_expired(timer) &&
			  (ret = mbedtls_ssl_write(&(tlsDataParams->ssl), pMsg + written_so_far, len - written_so_far)) <= 0) {
			if(ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
				IOT_ERROR(" failed\n  ! mbedtls_ssl_write returned -0x%x\n\n", -ret);
				/* All other negative return values indicate connection needs to be reset.
		 		* Will be caught in ping request so ignored here */
				isErrorFlag = true;
				break;
			}
		}
		if(isErrorFlag) {
			break;
		}
	}

	*written_len = written_so_far;

	if(isErrorFlag) {
		return NETWORK_SSL_WRITE_ERROR;
	} else if(has_timer_expired(timer) && written_so_far != len) {
		return NETWORK_SSL_WRITE_TIMEOUT_ERROR;
	}

	return SUCCESS;
}

IoT_Error_t iot_tls_read(Network *pNetwork, unsigned char *pMsg, size_t len, Timer *timer, size_t *read_len) {
	mbedtls_ssl_context *ssl = &(pNetwork->tlsDataParams.ssl);
	size_t rxLen = 0;
	int ret;

	while (len > 0) {
		// This read will timeout after IOT_SSL_READ_TIMEOUT if there's no data to be read
		ret = mbedtls_ssl_read(ssl, pMsg, len);
		if (ret > 0) {
			rxLen += ret;
			pMsg += ret;
			len -= ret;
		} else if (ret == 0 || (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE && ret != MBEDTLS_ERR_SSL_TIMEOUT)) {
			return NETWORK_SSL_READ_ERROR;
		}

		// Evaluate timeout after the read to make sure read is done at least once
		if (has_timer_expired(timer)) {
			break;
		}
	}

	if (len == 0) {
		*read_len = rxLen;
		return SUCCESS;
	}

	if (rxLen == 0) {
		return NETWORK_SSL_NOTHING_TO_READ;
	} else {
		return NETWORK_SSL_READ_TIMEOUT_ERROR;
	}
}

IoT_Error_t iot_tls_disconnect(Network *pNetwork) {
	mbedtls_ssl_context *ssl = &(pNetwork->tlsDataParams.ssl);
	int ret = 0;
	do {
		ret = mbedtls_ssl_close_notify(ssl);
	} while(ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	/* All other negative return values indicate connection needs to be reset.
	 * No further action required since this is disconnect call */

	return SUCCESS;
}

IoT_Error_t iot_tls_destroy(Network *pNetwork) {
	TLSDataParams *tlsDataParams = &(pNetwork->tlsDataParams);

	mbedtls_net_free(&(tlsDataParams->server_fd));

	mbedtls_x509_crt_free(&(tlsDataParams->clicert));
	mbedtls_x509_crt_free(&(tlsDataParams->cacert));
	mbedtls_pk_free(&(tlsDataParams->pkey));
	mbedtls_ssl_free(&(tlsDataParams->ssl));
	mbedtls_ssl_config_free(&(tlsDataParams->conf));
	mbedtls_ctr_drbg_free(&(tlsDataParams->ctr_drbg));
	mbedtls_entropy_free(&(tlsDataParams->entropy));

	return SUCCESS;
}

#ifdef __cplusplus
}
#endif
