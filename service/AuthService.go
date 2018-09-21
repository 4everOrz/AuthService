package service

import (
	"AuthService/common/config"
	_ "AuthService/common/logs"
	"AuthService/controllers"
	"AuthService/models"
	"encoding/json"
	"fmt"
	"math/rand"
	"unsafe"

	//"os"
	"security"
	"time"

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
#include "openssl/rsa.h"
#include "openssl/crypto.h"
#include "openssl/x509.h"
#include "openssl/pem.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

int err;
SOCKET listen_sock;
SSL_CTX* ctx;
struct sockaddr_in sa_serv;
struct sockaddr_in sa_cli;
//ssl初始化
int init(char *ca_cert, char *server_cert, char *server_key, char *key_password) {
	SSL_load_error_strings();            //为打印调试信息作准备
	OpenSSL_add_ssl_algorithms();        //初始化
	OpenSSL_add_all_ciphers();           //支持的算法
	OpenSSL_add_all_digests();
	ERR_load_CRYPTO_strings();

	//创建ctx上下文，并指定采用什么协议(SSLv2/SSLv3/TLSv1)
	ctx = SSL_CTX_new(SSLv23_server_method());
	if(!ctx)
	{
		ERR_print_errors_fp(stderr);
		exit(1);
	}else
	{
		printf("make a new ctx ok!\n");
	}
    //验证与否
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
	//若验证,则放置CA证书
	if(SSL_CTX_load_verify_locations(ctx, ca_cert, "2")<=0)
	{
		SSL_CTX_free(ctx);
        ERR_print_errors_fp(stderr);
		exit(1);
	}else
	{
		printf("load ca_cert ok!\n");
	}


    //加载自己的证书文件
	if (SSL_CTX_use_certificate_file(ctx, server_cert, SSL_FILETYPE_PEM) <= 0)
	{
       SSL_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		exit(1);
	}else
	{
		printf("load server_cert ok!\n");
	}

    //加载自己的私钥,以用于签名
	SSL_CTX_set_default_passwd_cb_userdata(ctx, key_password);
	if (SSL_CTX_use_PrivateKey_file(ctx, server_key, SSL_FILETYPE_PEM) <= 0)
	{
		SSL_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		exit(1);
	}else
	{
		printf("load server_key ok!\n");
	}
    //校验公私钥是否配对
	if (!SSL_CTX_check_private_key(ctx)) {
		SSL_CTX_free(ctx);
		printf("Private key does not match the certificate public key/n");
		exit(1);
	}else
	{
		printf("check_private_key ok!\n");
	}
	//处理握手多次
	SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
	return 1;
}
//开启监听
int ssl_tls_listen(char *ip,char *port) {
	//初始化网络环境，使用2.2版本scoket
	WSADATA wsaData;
	if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
	{
		printf("WSAStartup()fail:%d\n", GetLastError());
		return -1;
	}

	//开始正常的TCP socket过程.................................
    //scoket套接字
	if ((listen_sock = socket(AF_INET, SOCK_STREAM, 0))==-1)
	{
	   ERR_print_errors_fp(stderr);
	 	return -1;
	}
	memset(&sa_serv, 0, sizeof(sa_serv));
	sa_serv.sin_family = AF_INET;
	sa_serv.sin_addr.s_addr = inet_addr(ip);
	sa_serv.sin_port = htons(atoi(port));

	if (bind(listen_sock, (struct sockaddr*) &sa_serv,sizeof(sa_serv))==-1)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}

	//接受TCP链接
	if(listen(listen_sock, 5)==-1)
	{
		ERR_print_errors_fp(stderr);
		return -1;
	}
	return 1;
}
//接受连接
SSL* ssl_tls_accept(int *sd,int *flag)
{
	int sock;
	SSL*  ssl;
	int client_len = sizeof(sa_cli);
	sock = (int)accept(listen_sock, (struct sockaddr*) &sa_cli, &client_len);
	*sd = sock;
	if(sock==-1)
	{
	   ERR_print_errors_fp(stderr);
	   return NULL;
	}
	//TCP连接已建立,进行服务端的SSL过程.

	//申请一个SSL套接字
	if((ssl=SSL_new(ctx))==NULL)
	{
		closesocket(sock);
		return NULL;
	}
	//绑定读写套接字
	SSL_set_fd(ssl, sock);
     //完成握手过程
	*flag=SSL_accept(ssl);
	return ssl;
}

char* get_client_ip() {
   return inet_ntoa(sa_cli.sin_addr);
}

int get_client_port() {
	return ntohs(sa_cli.sin_port);
}
//获取证书序列号
char *serial;
ASN1_INTEGER *asn1_i;
char *get_cert_serial(SSL* ssl){
	X509 *client_cert = SSL_get_peer_certificate(ssl);//从SSL结构中提取出对方的证书解析成X509结构.
	if (client_cert != NULL) {
		asn1_i = X509_get_serialNumber(client_cert);
	    BIGNUM *bignum = ASN1_INTEGER_to_BN(asn1_i, NULL);
		serial = BN_bn2hex(bignum);
        BN_free(bignum);
	    X509_free (client_cert);
	    return serial;
	}
	else{
		printf("Client does not have certificate.\n");
		return NULL;
	}
}
//读取消息
char buf[1024*10];
char* read(SSL* ssl) {
	err = SSL_read(ssl, buf, sizeof(buf));   //读取数据
	if(err==-1)
	{
		return NULL;
	}

	//printf("Got %d chars:'%s'\n", err, buf);
	return buf;
}
//写入消息
int write(SSL* ssl,char *data) {
	err = SSL_write(ssl, data, strlen(data));
		return err;
}
//释放客户端连接资源
void closeSSL(SSL* ssl,int sd){
	SSL_shutdown(ssl);
	SSL_free(ssl);
	shutdown(sd,2);
	closesocket(sd);
	memset(&buf, '\0', sizeof(buf));
}
//关闭监听
void closeListenSock(){
	SSL_CTX_free(ctx);
	closesocket(listen_sock);
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

//初始化C代码，读取本地证书等操作
func init() {
	initflag := C.init(C.CString(config.GetString("svr_ca_file")), C.CString(config.GetString("svr_cert_file")),
		C.CString(config.GetString("svr_key_file")), C.CString(config.GetString("svr_key_password")))
	if initflag == 1 {
		fmt.Println("C-code init ok!")
	} else {
		fmt.Println("C-code init failed!")
		return
	}
}

//认证监听服务
func AuthServiceStart() {
	//开启TLS监听
	listenflag := C.ssl_tls_listen(C.CString(config.GetString("auth_listen_ip")), C.CString(config.GetString("auth_listen_port")))
	if listenflag == 1 {
		fmt.Println("AuthService listening...at port:", config.GetString("auth_listen_port"))
	} else {
		logs.Error("Start TLS listen failed!")
	}

	for {
		var sd, flag C.int
		flag = 1
		//阻塞等待连接
		ssl := C.ssl_tls_accept(&sd, &flag)
		fmt.Println("***********************************************")
		if ssl == nil {
			continue
		} else {
			switch flag {
			case 1:
				logs.Info("AuthService-RemoteIP:" + C.GoString(C.get_client_ip()))
				go PackageHandle(ssl, sd)
				continue
			case 0:
				logs.Error("The Handshake failed and was closed exactly ")
				C.closeSSL(ssl, sd)
				continue
			default:
				logs.Error("The handshake failed because a fatal error occurred at the protocol layer or connection failure.")
				C.closeSSL(ssl, sd)
				continue
			}
		}
	}
	C.closeListenSock()
}

//处理数据包（核心函数）
func PackageHandle(ssl *C.SSL, sd C.int) {
	var respData string
	devInfo := DevInfo{}
	receiveData := []byte(C.GoString(C.read(ssl)))
	if receiveData != nil {
		//解析Pack外包
		devInfoByte, err := ParesReq(receiveData)
		if err != nil {
			logs.Error("Error on parse pack package:", err)
			C.closeSSL(ssl, sd)
			return
		}
		//监控包不参与解析
		if devInfoByte == nil {
			logs.Info("Catched a Deamon package,will abandon it!")
			C.closeSSL(ssl, sd)
			return
		}
		//解析devInfo包
		logs.Info("devInfo_package:" + string(devInfoByte))
		if err = json.Unmarshal(devInfoByte, &devInfo); err != nil {
			logs.Error("Error on parse devInfo package:", err)
			C.closeSSL(ssl, sd)
			return
		}
		//校验字段
		if devInfo.Uuid == "" || devInfo.Mac == "" || devInfo.Licence == "" || devInfo.Ccode == "" {
			logs.Error("Lose some necessary fields like Uuid,Mac...")
			C.closeSSL(ssl, sd)
			return
		}
		//获取证书序列号
		serialpt := C.get_cert_serial(ssl)
		defer C.free(unsafe.Pointer(serialpt))
		serial := C.GoString(serialpt)
		if serial == "" {
			logs.Error("No serial in Cert")
			C.closeSSL(ssl, sd)
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
		respDatapt := C.CString(respData)
		defer C.free(unsafe.Pointer(respDatapt))
		if C.write(ssl, respDatapt) == -1 {
			logs.Error("Write scoket error!")
		}
		C.closeSSL(ssl, sd)
	} else {
		logs.Info("Connection is good,but no data!")
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
