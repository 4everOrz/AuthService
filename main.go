package main

import (
	"AuthService/service"
)

func main() {
	go service.AuthServiceStart() //开启身份认证服务
	service.DataServiceStart()    //数据转发服务
}
