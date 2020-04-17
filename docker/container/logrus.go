package container

import (
	log "github.com/sirupsen/logrus"
)

var logrus *log.Entry

func init() {
	logrus = log.WithFields(log.Fields{"origin": "libcompose"})
}
