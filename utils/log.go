package utils

import (
	"log"
	"os"
)

const (
	// Format holds the default log format
	logFormat = log.Ldate | log.Ltime
)

// Create logger instances for all log levels
var (
	DebugLogger = log.New(os.Stdout, "DEBUG ", logFormat)
	InfoLogger  = log.New(os.Stdout, "INFO ", logFormat)
	WarnLogger  = log.New(os.Stdout, "WARN ", logFormat)
	ErrorLogger = log.New(os.Stdout, "ERROR ", logFormat)
	FatalLogger = log.New(os.Stdout, "FATAL ", logFormat)
)
