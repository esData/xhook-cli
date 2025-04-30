// Banner
package banner

import (
	"fmt"
)

var BuildTime string
var Version = "DEV"
var GoVersion = "local"

func PrintRev() {
	fmt.Println("\n__  ___   _  ___   ___  _  __      ____ _     ___")
	fmt.Println("\\ \\/ / | | |/ _ \\ / _ \\| |/ /     / ___| |   |_ _|")
	fmt.Println(" \\  /| |_| | | | | | | | ' /_____| |   | |    | |")
	fmt.Println(" /  \\|  _  | |_| | |_| | . \\_____| |___| |___ | |")
	fmt.Println("/_/\\_\\_| |_|\\___/ \\___/|_|\\_\\     \\____|_____|___|")
	fmt.Println("  XHOOL-CLI, ver: " + Version + "(" + GoVersion + "), " + "Build: " + BuildTime)
}
