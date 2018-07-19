package db

import (
	"AuthService/common/config"
	"fmt"

	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/mysql"
)

var Orm *gorm.DB

func init() {
	var err error
	dataSourceName := config.GetString("db_user") + ":" + config.GetString("db_password") + "@tcp(" +
		config.GetString("db_ip") + ":" + config.GetString("db_port") + ")/" +
		config.GetString("db_name") + "?charset=utf8"
	Orm, err = gorm.Open("mysql", dataSourceName)
	if err != nil {
		fmt.Println("mysql init failed!！error:" + err.Error())
		return
	}
	Orm.DB().SetMaxIdleConns(10)
	Orm.DB().SetMaxOpenConns(100)
	fmt.Println("mysql init ok! ")

}
