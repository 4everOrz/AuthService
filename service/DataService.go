package service

import (
	"AuthService/common/config"
	"C"
	"encoding/json"
	"net"

	logs "github.com/alecthomas/log4go"
)
import "fmt"

//接收数据
func receive(conn *net.TCPConn) []byte {
	data := make([]byte, 1024)
	i, err := conn.Read(data)
	if err != nil {
		logs.Error("Error on BufReader:", err)
		return nil
	}
	return data[0:i]
}

//发送数据
func send(conn *net.TCPConn, data []byte) {
	if _, err := conn.Write(data); err != nil {
		logs.Error(err)
		return
	}

	if err := conn.CloseWrite(); err != nil {
		logs.Error(err)
		return
	}
}

//数据转发
func transmitService(data []byte) []byte {
	addr, err := net.ResolveTCPAddr("tcp", config.GetString("data_acquisition_server_ip")+":"+config.GetString("data_acquisition_server_port"))
	if err != nil {
		logs.Error("Error on ResolveTCPAddr: ", err)
		return nil
	}
	dataTransmitConn, err := net.DialTCP("tcp", nil, addr)
	if err != nil {
		logs.Error("Error on DialTCP: ", err)
		return nil
	}
	send(dataTransmitConn, data)
	if err := dataTransmitConn.Close(); err != nil {
		logs.Error("Error on CloseConn:", err)
	}
	return receive(dataTransmitConn)
}

//设备数据包处理程序
func dataHandler(conn *net.TCPConn) {
	var respData []byte
	data := receive(conn)
	devInfo := DevInfo{}
	devInfoByte, err := ParesReq(data)
	if err != nil {
		logs.Error("Paresing data error:", err)
		return
	}
	if err = json.Unmarshal(devInfoByte, &devInfo); err != nil {
		logs.Error("Error on parse devInfo package:", err)
		return
	}
	/*************数据转发********************/
	//	data = transmitService(data)
	/*******************************************/
	//	if string(data) == "+OK" {
	respData = Packing(2, devInfo.Mac, devInfo.Uuid)
	//	} else {
	//		respData = Packing(0, devInfo.Mac, devInfo.Uuid)
	//	}
	send(conn, respData)
}

//设备数据包监听服务
func DataServiceStart() {
	addr, err := net.ResolveTCPAddr("tcp", config.GetString("data_listen_ip")+":"+config.GetString("data_listen_port"))
	if err != nil {
		logs.Error("Error on ResolveTCPAddr:", err)
		return
	}
	listen, err := net.ListenTCP("tcp", addr)
	if err != nil {
		logs.Error("listen tcp error")
		return
	}
	fmt.Println("DataService listening...at port:", config.GetString("data_listen_port"))
	for {
		conn, err := listen.AcceptTCP()
		if err != nil {
			continue
		}
		logs.Info("%DataService%", "RemoteAddr：", conn.RemoteAddr().String(), " connected")
		defer func() {
			logs.Info("closing accept .....")
			conn.Close()
			logs.Info("shut down")
		}()
		go dataHandler(conn)
	}
}
