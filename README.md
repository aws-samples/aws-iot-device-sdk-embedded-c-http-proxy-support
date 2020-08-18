## HTTP Proxy Support for AWS IoT Device SDK for Embedded C

This project extends the [aws-iot-device-sdk-embedded-C release v3.0.1](https://github.com/aws/aws-iot-device-sdk-embedded-C/releases/tag/v3.0.1) library to support MQTT connections and operations via an HTTP proxy. Optionally, HTTP Basic Authentication may be enabled to authorize the proxy connection.

There is also a [sample application](https://github.com/aws-samples/aws-iot-device-sdk-embedded-C-http-proxy-support/tree/master/samples/linux/subscribe_publish_proxy_sample) that demonstrates how to enable HTTP proxy and perform MQTT subscribe and publish operations.

On a high level, the following new proxy-related parameters are added to the `IoT_Client_Init_Params` struct in [`include/aws_iot_mqtt_client.h`](https://github.com/aws-samples/aws-iot-device-sdk-embedded-c-http-proxy-support/blob/master/include/aws_iot_mqtt_client.h).


```
Proxy_Type_t proxyType; ///< By default proxy is disabled
char *pProxyHostURL; ///< Pointer to a string defining the host endpoint for the proxy server
uint16_t proxyPort; ///< Proxy server listening port
bool isAuthenticationRequired; ///< Set to true to enable username/password authentication
char *pProxyUserName; ///< Pointer to a string defining the username for proxy authentication
char *pProxyPassword; ///< Pointer to a string defining the password for proxy authentication
```


One can easily create an HTTP-proxy-enabled AWS IoT Client by providing these parameters upon client initialization. See the [sample application](https://github.com/aws-samples/aws-iot-device-sdk-embedded-C-http-proxy-support/tree/master/samples/linux/subscribe_publish_proxy_sample) for more information.
***

### Patch your existing SDK library

Copy the `patch.diff` file to your current SDK library directory and apply the patch under that directory:


```
git apply patch.diff
```


> ***NOTE:***  The patch file is based on the SDK version [Release v3.0.1](https://github.com/aws/aws-iot-device-sdk-embedded-C/releases/tag/v3.0.1). Any other versions or branches may not work.
***

### Build and run the sample application

#### Linux Ubuntu 18.04.4 LTS
All development and testing of the HTTP Proxy Sample has been performed on Linux Ubuntu 18.04.4 LTS.

#### Install dependencies


```
sudo apt-get update
sudo apt-get install build-essential \
                     python \
                     clang
```


#### Get AWS IoT Device SDK For Embedded C library (release version 3.0.1)

Download the [SDK library v3.0.1](https://github.com/aws/aws-iot-device-sdk-embedded-C/releases/tag/v3.0.1) and unzip the archive.



#### Get mbedTLS
Under the SDK root directory, run:


```
wget -qO- https://github.com/ARMmbed/mbedtls/archive/mbedtls-2.16.7.tar.gz | tar xvz -C external_libs/mbedTLS --strip-components=1
```

#### Apply patch to the SDK
Copy the `patch.diff` file to the SDK root directory and apply the patch under that directory:


```
git apply patch.diff
```

#### Copy the sample application to SDK library
Copy the `samples` directory to the SDK root directory.

#### Configure the SDK with your device parameters


1. [Create and Activate a Device Certificate](https://docs.aws.amazon.com/iot/latest/developerguide/create-device-certificate.html)
2. Copy the certificate, private key, and root CA certificate you created into the [`/certs`](https://github.com/aws-samples/aws-iot-device-sdk-embedded-C-http-proxy-support/tree/master/certs) directory.
3. You must configure the sample with your own AWS IoT endpoint, private key, certificate, and root CA certificate. Proxy parameters are also configured here. Make those changes in the [`samples/linux/subscribe_publish_proxy_sample/aws_iot_config.h`](https://github.com/aws-samples/aws-iot-device-sdk-embedded-C-http-proxy-support/blob/master/samples/linux/subscribe_publish_proxy_sample/aws_iot_config.h) file. Open the `aws_iot_config.h` file, update the values for the following:

```
// Get from console
// =================================================
#define AWS_IOT_MQTT_HOST              "YOUR_ENDPOINT_HERE" ///< Customer specific MQTT HOST. The same will be used for Thing Shadow
#define AWS_IOT_MQTT_PORT              443 ///< default port for MQTT/S
#define AWS_IOT_MQTT_CLIENT_ID         "YOUR_CLIENT_ID" ///< MQTT client ID should be unique for every device
#define AWS_IOT_MY_THING_NAME          "YOUR_THING_NAME" ///< Thing Name of the Shadow this device is associated with
#define AWS_IOT_ROOT_CA_FILENAME       "rootCA.crt" ///< Root CA file name
#define AWS_IOT_CERTIFICATE_FILENAME   "cert.pem" ///< device signed certificate file name
#define AWS_IOT_PRIVATE_KEY_FILENAME   "privkey.pem" ///< Device private key filename
#define HTTP_PROXY_HOST                "127.0.0.1" ///< endpoint of HTTP proxy server
#define HTTP_PROXY_PORT                1080 ///< port of HTTP proxy server
#define HTTP_PROXY_AUTH_ENABLE         1 ///< set to 1 to enable proxy authentication
#define HTTP_PROXY_USERNAME            "proxyUsername" ///< Username for proxy authentication
#define HTTP_PROXY_PASSWORD            "proxyPassword" ///< Password for proxy authentication
// =================================================
```



#### Building the download agent sample


```
cd samples/linux/subscribe_publish_proxy_sample
make -j4
./subscribe_publish_proxy_sample
```

***

### Limitations
* The sum of the proxy username and password lengths are limited to 63 bytes long excluding the terminating null character.
* A buffer of 310 bytes would be used for the HTTP proxy connection.
* A static buffer of 2KB would be used for debug logs when the debug flag is enabled.
* The library is designed to be used with an HTTP proxy in a trusted network. Therefore the HTTP Connect Request is not sent with TLS encryption. This means the request (including the authentication credentials) may be intercepted and read by somebody else when accessing a remote proxy in a non-trusted network.

***

### License

This project is licensed under the Apache-2.0 License.


