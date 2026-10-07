// Package output provides the scaffolding for terminal output and formatting.
package output

import "fmt"

// PrintInfo prints a placeholder informational message.
func PrintInfo(msg string) {
	fmt.Println(msg)
}
