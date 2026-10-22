//go:build !linux

package main

import "os"

// Distribution targets Linux; other platforms retain explicit plain output.
func terminalColumns(*os.File) int { return 0 }
