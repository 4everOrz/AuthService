package controllers

import (
	//log "AuthService/common/logs"
	"AuthService/models"

	logs "github.com/alecthomas/log4go"
)

type AuthController struct {
	Module models.DevCertSerialInfo
}

/*认证证书序列号与模块信息的对应关系
查询数据库时，若：
1 证书序列号不存在
1.1 模块信息不存在（模块做第一次认证）
    存储证证书序列号与模块信息，返回true。
1.2 模块信息存在(模块已注册过，认证过，跟当前上传证书不一致)
    返回false
2 证书序列号存在
2.1 证书序列号与模块信息完全匹配（模块做第n次认证）
   返回true。
2.2 证书序列号与模块信息不完全匹配（证书不能用在多个模块里）
   返回false
*/

/* 认证处理程序*/
func (auth AuthController) AuthHandler() bool {
	module := auth.Module
	certinfo, count := module.GetEntityBySerial()
	if count == 0 { //证书序列号不存在
		_, count := module.GetEntityByFields()
		if count != 0 { //模块信息已存在
			logs.Info("module already exists, return false")
			return false
		} else { //模块信息不存在
			module.Flag = 1
			if err := module.Create(); err != nil {
				logs.Error("insert one failed:", err)
				return false
			} else {
				logs.Info("first authentication, return true")
				return true
			}
		}
	} else { //证书序列号存在
		if certinfo.Uuid == module.Uuid && certinfo.Mac == module.Mac && certinfo.Licence == module.Licence && certinfo.Ccode == module.Ccode { //模块信息相匹配
			logs.Info("serialNumber and module information match, return true")
			return true
		} else {
			logs.Info("serialNumber and module information do not match, return false")
			return false
		}
	}
}
