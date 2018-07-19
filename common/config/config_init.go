package config

import (
	"fmt"

	"github.com/kylelemons/go-gypsy/yaml"
)

var ConfigFile *yaml.File

func init() {
	var err error
	ConfigFile, err = yaml.ReadFile("config/config.yaml")
	if err != nil {
		fmt.Println("read config file failed!")
	}
	fmt.Println("config init ok!")
}
func GetString(key string) string {
	str, err := ConfigFile.Get(key)
	if err != nil {
		fmt.Println("read configfile failed!")
	}
	return str
}
