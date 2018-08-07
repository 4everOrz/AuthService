package models

import (
	"AuthService/common/db"
)

//http://gorm.io/docs/

type DevCertSerialInfo struct {
	ID      int64  `gorm:"type:bigint;primary_key;AUTO_INCREMENT;not null;"`
	Ctime   string `gorm:"type:timestamp;null;"`
	Serial  string `gorm:"type:varchar(20);null;"`
	Uuid    string `gorm:"type:varchar(30);null;"`
	Mac     string `gorm:"type:varchar(12);null;"`
	Licence string `gorm:"type:varchar(50);null;"`
	Ccode   string `gorm:"type:varchar(20);null;"`
	Flag    int    `gorm:"type:tinyint(2);null;"`
}

/*
func init() {
	if !db.Orm.HasTable(&DevCertSerialInfo{}) {
		if err := db.Orm.Set("gorm:DevCertSerialInfo", "ENGINE=InnoDB DEFAULT CHARSET=utf8").CreateTable(&DevCertSerialInfo{}).Error; err != nil {
			fmt.Println("Create table failed,error:" + err.Error())
		}
	}
}*/

//添加一条记录
func (devcertserialInfo *DevCertSerialInfo) Create() error {
	if err := db.Orm.Create(&devcertserialInfo).Error; err != nil {
		return err
	}
	return nil
}

//删除一条记录
func (entity DevCertSerialInfo) Delete() error {
	if err := db.Orm.Where(&DevCertSerialInfo{Mac: ""}).Delete(DevCertSerialInfo{}).Error; err != nil {
		return err
	}
	return nil
}

//获取一条记录
func (devcertserialInfo DevCertSerialInfo) GetEntityBySerial() (DevCertSerialInfo, int64) {
	var count int64
	var entity = DevCertSerialInfo{}
	db.Orm.Where(&DevCertSerialInfo{Serial: devcertserialInfo.Serial}).Find(&entity).Count(&count)
	return entity, count
}

// 获取一条记录
func (devcertserialInfo DevCertSerialInfo) GetEntityByFields() (DevCertSerialInfo, int64) {
	var count int64
	var entity = DevCertSerialInfo{}
	db.Orm.Where(&DevCertSerialInfo{Uuid: devcertserialInfo.Uuid, Mac: devcertserialInfo.Mac, Licence: devcertserialInfo.Licence, Ccode: devcertserialInfo.Ccode}).Find(&entity).Count(&count)
	return entity, count
}

//更新一条记录
func (devcertserialInfo DevCertSerialInfo) Update() {

	db.Orm.Model(DevCertSerialInfo{}).Updates(DevCertSerialInfo{Mac: "242353654"})

}

//返回表名
func (devcertserialInfo DevCertSerialInfo) TableName() string {
	return "DevCertSerialInfo"
}
