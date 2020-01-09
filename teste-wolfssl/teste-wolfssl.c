#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/test.h>
#include <errno.h>
#include <stdio.h>

#define LOCAL_TEST
#define USE_FILE_CERT "tago_cert.pem"


#ifndef LOCAL_TEST
#define SERV_PORT 443//1500//1111
#else
#define SERV_PORT 1500
#endif

const unsigned char tago_cert[] = {
		"-----BEGIN CERTIFICATE-----\n"
		"MIIEojCCA4qgAwIBAgITBn+UV0u3B10+SJZceDIkqnVP7TANBgkqhkiG9w0BAQsF\n"
		"ADCBmDELMAkGA1UEBhMCVVMxEDAOBgNVBAgTB0FyaXpvbmExEzARBgNVBAcTClNj\n"
		"b3R0c2RhbGUxJTAjBgNVBAoTHFN0YXJmaWVsZCBUZWNobm9sb2dpZXMsIEluYy4x\n"
		"OzA5BgNVBAMTMlN0YXJmaWVsZCBTZXJ2aWNlcyBSb290IENlcnRpZmljYXRlIEF1\n"
		"dGhvcml0eSAtIEcyMB4XDTE1MTAyMjAwMDAwMFoXDTI1MTAxOTAwMDAwMFowRjEL\n"
		"MAkGA1UEBhMCVVMxDzANBgNVBAoTBkFtYXpvbjEVMBMGA1UECxMMU2VydmVyIENB\n"
		"IDBBMQ8wDQYDVQQDEwZBbWF6b24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
		"AoIBAQChhTHcMX+WcSKio/2VJ8N0cCpdrUf4oB9V+fx2dFxU+XgRvszhgePcNKv5\n"
		"d7a0qOWF9uLmYix0BP34xYujNe0TTGBjOdjCWmTLi9mb5gO8Qxe3eaPZFHX2JbA+\n"
		"GeqyLkv3/Dt4SkggAZX1PvoaPlCytHCW7qDdo+ycuqwrrfl0fYfJrEA+O5x8v+uH\n"
		"UmC5APF5vYE8XdGhGra5JRot2TY3P+Kh1AfuJWPLBRgmmbPscv81zVdl+LzZdGFP\n"
		"dCnCwE9OKd4stKNkO2vTwdJykLgovcF889LQdbPfCx7UaDeHdAcJLyNcS0i5FrHD\n"
		"7hNfwzfpOORF0+1wF6HdE/GBUJBJAgMBAAGjggE0MIIBMDASBgNVHRMBAf8ECDAG\n"
		"AQH/AgEAMA4GA1UdDwEB/wQEAwIBhjAdBgNVHQ4EFgQUl+rEItIGGO2FBP/cUsJu\n"
		"2w4G4T8wHwYDVR0jBBgwFoAUnF8A36oB1zArOIiiuG1KnPIRkYMweAYIKwYBBQUH\n"
		"AQEEbDBqMC4GCCsGAQUFBzABhiJodHRwOi8vb2NzcC5yb290ZzIuYW1hem9udHJ1\n"
		"c3QuY29tMDgGCCsGAQUFBzAChixodHRwOi8vY3J0LnJvb3RnMi5hbWF6b250cnVz\n"
		"dC5jb20vcm9vdGcyLmNlcjA9BgNVHR8ENjA0MDKgMKAuhixodHRwOi8vY3JsLnJv\n"
		"b3RnMi5hbWF6b250cnVzdC5jb20vcm9vdGcyLmNybDARBgNVHSAECjAIMAYGBFUd\n"
		"IAAwDQYJKoZIhvcNAQELBQADggEBAK/GJ9NNlVof/45Jo9qouxV79fiyONjw5Kym\n"
		"nZpko27O2TQwnSN4xguhR9qPCLJFfzxpybjZK52+bpNpXbWOoZKEsXIFxShocXmx\n"
		"xY3jpQRDijIqyB1wEEYV/0S4J6dGtdx9xb/t1L6/53ogFPa17v+dFhJQ0WwIzfTW\n"
		"R/Vox5ZrJ/sgBIgylEJWsEUX0hc+QwryeGU9Ylv2XIcmANzoH2tQnHs1v8GG3FYY\n"
		"RZ4FeoPETzXfKd98y0l9v6lx2guQ4hNA3vCYDMF+w/2TcVW6YPVMjEkuRN2hypcY\n"
		"uNmaqaMA0K0ZD7nQOedXceNRfr+GruHRduh2EZI0gMxfOpwfn98=\n"
		"-----END CERTIFICATE-----\n"
};
int sockfd;

int cbk_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx){
	printf(">>cbk_recv\n");
	return recv(sockfd, buf, sz, 0);
}
int cbk_send(WOLFSSL *ssl, char *buf, int sz, void *ctx){
	printf(">>cbk_send\n");
	return send(sockfd, buf, sz, 0);
}



int main()
{
	//int sockfd;
	WOLFSSL_CTX* ctx;
	WOLFSSL* ssl;
	WOLFSSL_METHOD* method;
	struct  sockaddr_in servAddr;
	const char message[] = 
		"POST /data HTTP/1.1\r\n"
		"Host: api.tago.io\r\n"
		"content-type: application/json\r\n"
		"content-length: 34\r\n"
		"device-token: c7f71928-9510-4cda-9c69-29a0e35d44b9\r\n\r\n"
		"{\"variable\":\"board\";\"value\":\"375\"}";

	/* create and set up socket */
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	memset(&servAddr, 0, sizeof(servAddr));
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(SERV_PORT);
#ifndef LOCAL_TEST
	servAddr.sin_addr.s_addr = inet_addr("api.tago.io");
#else
	servAddr.sin_addr.s_addr = inet_addr("192.168.222.192");
#endif

	printf("Connect to socket\n");
    /* connect to socket */
	connect(sockfd, (struct sockaddr *) &servAddr, sizeof(servAddr));

	printf("wolfssl_init \n");
    /* initialize wolfssl library */
	wolfSSL_Init();
	method = wolfTLSv1_2_client_method(); /* use TLS v1.2 */

	printf("wolfssl_ctx_new \n");
    /* make new ssl context */
	if ( (ctx = wolfSSL_CTX_new(method)) == NULL) {
	      err_sys("wolfSSL_CTX_new error");
	}

	printf("wolfssl_new \n");
    /* make new wolfSSL struct */
	if ( (ssl = wolfSSL_new(ctx)) == NULL) {
	     err_sys("wolfSSL_new error");
	}

	printf("wolfssl_ctx_load \n");
    /* Add cert to ctx */
#ifdef USE_FILE_CERT
	 if (wolfSSL_CTX_load_verify_locations(ctx, USE_FILE_CERT, 0) !=SSL_SUCCESS) {
#else
	if (wolfSSL_CTX_load_verify_buffer(ctx, tago_cert, sizeof(tago_cert), SSL_FILETYPE_PEM) != SSL_SUCCESS) {
#endif
	     err_sys("Error loading certs/ca-cert.pem");
	}

	wolfSSL_SetIOSend(ctx, cbk_send);
	wolfSSL_SetIORecv(ctx, cbk_recv);

	printf("wolfssl_set \n");
    /* Connect wolfssl to the socket, server, then send message */
	wolfSSL_set_fd(ssl, sockfd);
	printf("wolfssl_connect \n");
	printf("return connect:%d\n",wolfSSL_connect(ssl));
	printf("wolfssl_write \n");
	wolfSSL_write(ssl, message, strlen(message));

    /* frees all data before client termination */
	printf("wolfssl_free \n");
	wolfSSL_free(ssl);
	wolfSSL_CTX_free(ctx);
	wolfSSL_Cleanup();

	printf("exit \n");
}
