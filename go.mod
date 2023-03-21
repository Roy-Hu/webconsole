module github.com/free5gc/webconsole

go 1.14

require (
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/fclairamb/ftpserver v0.12.1
	github.com/fclairamb/ftpserverlib v0.20.0
	github.com/fclairamb/go-log v0.4.1
	github.com/free5gc/CDRUtil v0.0.0
	github.com/free5gc/TarrifUtil v0.0.0
	github.com/free5gc/openapi v1.0.5
	github.com/free5gc/util v1.0.1
	github.com/gin-contrib/cors v1.3.1
	github.com/gin-gonic/gin v1.7.3
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/google/uuid v1.3.0
	github.com/jlaffaye/ftp v0.1.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.9.0
	github.com/urfave/cli v1.22.5
	go.mongodb.org/mongo-driver v1.7.1
	golang.org/x/crypto v0.0.0-20220924013350-4ba4fb4dd9e7
	gopkg.in/yaml.v2 v2.4.0
)

replace github.com/free5gc/CDRUtil v0.0.0 => /home/free5gc/CDRUtil

replace github.com/free5gc/TarrifUtil v0.0.0 => /home/free5gc/TarrifUtil
