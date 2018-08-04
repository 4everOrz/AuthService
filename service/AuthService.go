package service

import (
	"AuthService/controllers"
	"AuthService/models"
	"AuthTest/common/config"
	_ "AuthTest/common/logs"
	"encoding/json"
	"fmt"
	"math/rand"
	"security"
	"time"
	"unsafe"

	logs "github.com/alecthomas/log4go"
)

/*
#cgo CFLAGS : -I../include
#cgo windows LDFLAGS: -L../lib -llibeay32 -lssleay32 -lWS2_32

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <errno.h>
#include <sys/types.h>
#include <winsock2.h>
#include <Windows.h>
#include "openssl/bio.h"
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

SOCKET svrsock;
SSL_CTX *ctx;
struct sockaddr_in my_addr;
struct sockaddr_in their_addr;
//ssl初始化
int ssl_init(char *ca_cert, char *server_cert, char *server_key, char *key_password)
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(SSLv23_server_method());
  //ctx = SSL_CTX_new(TLSv1_2_server_method());
    if (ctx == NULL) {

		return 0;
    }
    //验证与否
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	//若验证,则放置CA证书
	if(SSL_CTX_load_verify_locations(ctx, ca_cert, NULL)<=0)
     {
		SSL_CTX_free(ctx);
         ERR_print_errors_fp(stderr);
	     return 0;
	}
	else
	{
		printf("load ca_cert ok!\n");
	}
    if (SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM) <= 0) {
       return 0;
    }
    SSL_CTX_set_default_passwd_cb_userdata(ctx, key_password);
	if (SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM) <= 0){
        return 0;
    }
    if (!SSL_CTX_check_private_key(ctx)) {
        return 0;
	}
	SSL_CTX_set_mode(ctx,SSL_MODE_AUTO_RETRY);
	return 1;
}
//开始监听
int tls_listener(char *ip,char *port){
	//初始化网络环境，使用2.2版本scoket
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("WSAStartup()fail:%d\n", GetLastError());
		return -1;
	}

    if ((svrsock = socket(AF_INET, SOCK_STREAM,IPPROTO_TCP)) == -1) {
        perror("socket");
        return 0;
    }

    memset(&my_addr, 0,sizeof(my_addr));
    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(atoi(port));
    my_addr.sin_addr.s_addr  = inet_addr(ip);

    if (bind(svrsock, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))== -1) {
        perror("bind");
         return 0;
    }

    if (listen(svrsock, 5) == -1) {
        perror("listen");
        return 0;
    }
	ERR_remove_state(0);
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();
	return 1;
}
//接受客户端连接
SSL* tls_accept(int *clisock){
	SSL* ssl;
	 memset(&their_addr, 0,sizeof(their_addr));
     int len= sizeof(struct sockaddr);
	if ((*clisock =(int)accept(svrsock, (struct sockaddr *) &their_addr,&len)) == -1){
	    perror("accept");
		return 0;
	}
    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, *clisock);
	if (SSL_accept(ssl) == -1) {
        perror("accept");
        closesocket(*clisock);
        return 0;
	}
	ERR_remove_state(0);
	ERR_free_strings();
	CRYPTO_cleanup_all_ex_data();
    return ssl;
}

//接收数据
char buf[1024];
char* tls_read(SSL* ssl){
	int len;
    memset(buf, 0, sizeof(buf));
    len = SSL_read(ssl, buf,sizeof(buf)-1);
	if (len > 0)
	{
		printf("got:'%s'，byte:%d \n",buf, len);
	}
	buf[len]='\0';
	return buf;
}
//发送数据
int tls_write(SSL* ssl,char *data) {
	int err = SSL_write(ssl, data, strlen(data));
	return err;
}
//获取证书序列号
char* get_cert_serial(SSL* ssl){
	char *serial;
	X509 *client_cert = SSL_get_peer_certificate(ssl);//从SSL结构中提取出对方的证书解析成X509结构.
	if (client_cert != NULL) {
		ASN1_INTEGER *asn1_i = X509_get_serialNumber(client_cert);
	    BIGNUM *bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
		serial = BN_bn2hex(bignum);
		BN_free(bignum);

	}else{
		printf("Client does not have certificate.\n");
	}
	X509_free (client_cert);
	return serial;
}
//关闭当前客户端连接
void closeclisock(SSL* ssl,int clisock){
	SSL_shutdown(ssl);
	SSL_free(ssl);
	shutdown(clisock,2);
	closesocket(clisock);
	ERR_remove_state(0);
	ERR_free_strings();
    CRYPTO_cleanup_all_ex_data();
}
//结束监听
void closesvrsock(){
	closesocket(svrsock);
	SSL_CTX_free(ctx);
    WSACleanup();
}
*/
import "C"

//请求或答复外层数据包结构
type Pack struct {
	T    string `json:"t"`
	I    int    `json:"i"`
	Cid  string `json:"cid"`
	Tcid string `json:"tcid"`
	Pack string `json:"pack"`
}

//答复内层数据包结构
type AuthRet struct {
	T    string `json:"t"`
	Mac  string `json:"mac"`
	Uuid string `json:"uuid"`
	R    int    `json:"r"`
	Time string `json:"time"`
	Msg  string `json:"msg"`
}

//请求内层数据包结构
type DevInfo struct {
	T       string `json:"t"`
	Uuid    string `json:"uuid"`
	Mac     string `json:"mac"`
	Licence string `json:"licence"`
	Ccode   string `json:"ccode"`
}

func init() {
	svr_ca_file := C.CString(config.GetString("svr_ca_file"))
	svr_cert_file := C.CString(config.GetString("svr_cert_file"))
	svr_key_file := C.CString(config.GetString("svr_key_file"))
	svr_key_password := C.CString(config.GetString("svr_key_password"))

	if C.ssl_init(svr_ca_file, svr_cert_file, svr_key_file, svr_key_password) == 1 {
		fmt.Println("SSL_init ok!")
	} else {
		fmt.Println("SSL_init error!")
	}
	defer func() {
		C.free(unsafe.Pointer(svr_ca_file))
		C.free(unsafe.Pointer(svr_cert_file))
		C.free(unsafe.Pointer(svr_key_file))
		C.free(unsafe.Pointer(svr_key_password))
	}()
}

//认证服务
func AuthServiceStart() {
	auth_listen_ip := C.CString(config.GetString("auth_listen_ip"))
	auth_listen_port := C.CString(config.GetString("auth_listen_port"))
	defer func() {
		C.free(unsafe.Pointer(auth_listen_ip))
		C.free(unsafe.Pointer(auth_listen_port))
	}()
	//开启TLS监听
	if C.tls_listener(auth_listen_ip, auth_listen_port) == 1 {
		fmt.Println("AuthService listening...at port:", config.GetString("auth_listen_port"))
	} else {
		fmt.Println("AuthService listen  failed")
	}
	for {
		var clisock C.int
		ssl := C.tls_accept(&clisock)
		if ssl != nil {
			go PackageHandle(ssl, clisock)
		}
		defer C.free(unsafe.Pointer(ssl))
	}
	C.closesvrsock()
}

//处理数据包（核心函数）
func PackageHandle(ssl *C.SSL, clisock C.int) {
	var respData string
	devInfo := DevInfo{}
	receiveData := []byte(C.GoString(C.tls_read(ssl)))
	if receiveData != nil {
		//解析Pack外包
		devInfoByte, err := ParesReq(receiveData)

		if err != nil {
			logs.Error("Error on parse pack package:", err)
			C.closeclisock(ssl, clisock)
			return
		}
		//监控包不参与解析
		if devInfoByte == nil {
			logs.Info("Catched a Deamon package,will abandon it!")
			C.closeclisock(ssl, clisock)
			return
		}
		//解析devInfo包
		logs.Info("devInfo_package:" + string(devInfoByte))
		if err = json.Unmarshal(devInfoByte, &devInfo); err != nil {
			logs.Error("Error on parse devInfo package:", err)
			C.closeclisock(ssl, clisock)
			return
		}
		//校验字段
		if devInfo.Uuid == "" || devInfo.Mac == "" || devInfo.Licence == "" || devInfo.Ccode == "" {
			logs.Error("Lose some necessary fields like Uuid,Mac...")
			C.closeclisock(ssl, clisock)
			return
		}
		//获取证书序列号
		serialpt := C.get_cert_serial(ssl)
		serial := C.GoString(serialpt)
		if serial == "" {
			logs.Error("No serial in Cert")
			C.closeclisock(ssl, clisock)
			return
		} else {
			logs.Info("SerialNumber:" + string(serial))
		}
		//验证
		if devInfo.DevInfo2AuthController(serial).AuthHandler() {
			respData = string(Packing(1, devInfo.Mac, devInfo.Uuid))
		} else {
			respData = string(Packing(0, devInfo.Mac, devInfo.Uuid))
		}
		//返回答复包
		ans := C.CString(respData)
		if C.tls_write(ssl, ans) == -1 {
			logs.Error("Write scoket error!")
		}
		defer func() {
			C.free(unsafe.Pointer(ans))
			C.free(unsafe.Pointer(serialpt))
		}()
		C.closeclisock(ssl, clisock)

	} else {
		logs.Info("Connection is good,but no data!")
		C.closeclisock(ssl, clisock)
	}
}

//解析和解密Pack包
func ParesReq(data []byte) ([]byte, error) {
	var reqPack Pack
	err := json.Unmarshal(data, &reqPack)
	if reqPack.T == "monitor" { //表明是监视包，不参与解析，直接返回
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	packByte, err := security.AesDecrypt2([]byte(reqPack.Pack), reqPack.I)
	if err != nil {
		return nil, err
	}
	return packByte, nil
}

//加密和打包答复包
func Packing(flag int, mac, uuid string) []byte {
	authRet := AuthRet{
		R:    flag,
		T:    "authRet",
		Mac:  mac,
		Uuid: uuid,
		Time: time.Now().Format("2006-01-02 15:04:05")}
	data, _ := json.Marshal(authRet)
	logs.Info("authret_package:" + string(data))
	rand.Seed(time.Now().UnixNano()) //添加随机种子
	x := rand.Intn(4)
	EncryptKey_type := 11 + x
	enData := security.AesEncrypt(data, security.GetKey(EncryptKey_type))
	respPack := Pack{T: "pack", I: EncryptKey_type, Cid: mac, Pack: string(enData)}
	respData, _ := json.Marshal(respPack)
	return respData
}

//DevInfo转AuthController
func (devInfo DevInfo) DevInfo2AuthController(serial string) controllers.AuthController {
	var auth = controllers.AuthController{
		Module: models.DevCertSerialInfo{
			Ctime:   time.Now().Format("2006-01-02 15:04:05"),
			Uuid:    devInfo.Uuid,
			Mac:     devInfo.Mac,
			Licence: devInfo.Licence,
			Ccode:   devInfo.Ccode,
			Serial:  serial},
	}
	return auth
}

/**/
