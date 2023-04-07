package ftp

import (
	"io/ioutil"
	"time"

	"github.com/free5gc/webconsole/backend/logger"
	"github.com/jlaffaye/ftp"
)

func FTPLogin() (*ftp.ServerConn, error) {
	// FTP server is for CDR transfer
	var c *ftp.ServerConn

	c, err := ftp.Dial("127.0.0.113:2121", ftp.DialWithTimeout(5*time.Second))
	if err != nil {
		return nil, err
	}

	err = c.Login("admin", "free5gc")
	if err != nil {
		return nil, err
	}

	logger.FtpLog.Info("Login FTP server")
	return c, err
}

func FTPRetrv(c *ftp.ServerConn, fileName string) ([]byte, error) {
	r, err := c.Retr(fileName)
	if err != nil {
		logger.WebUILog.Warn("Fail to retrv file: ", fileName)
		return nil, err
	}

	defer r.Close()

	logger.FtpLog.Info("Retrv FTP file success")

	if err := c.Quit(); err != nil {
		return nil, err
	}

	cdr, err1 := ioutil.ReadAll(r)

	return cdr, err1
}
