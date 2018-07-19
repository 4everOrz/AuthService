package logs

import (
	"fmt"

	l4g "github.com/alecthomas/log4go"
)

func init() {

	l4g.LoadConfiguration("log/log4go_conf.xml")
	fmt.Println("log init ok!")
}
