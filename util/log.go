package util

import (
	"io"
	"log"
	"os"
)

var logger *log.Logger

func GetLogger(filepath string) (*log.Logger, error) {

	var writer io.Writer

	// log to custom filepath rather than syslog
	if filepath != "" {
		logFile, err := os.OpenFile(filepath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		// write to stdout and the logfile
		writer = io.MultiWriter(logFile, os.Stdout)
		logger = log.New(writer, "metatrapd: ", log.LstdFlags)

	} else {
		logger = log.New(os.Stdout, "metatrapd: ", log.LstdFlags)
	}

	return logger, nil
}
