module github.com/free5gc/webconsole

go 1.14

require (
	github.com/antonfisher/nested-logrus-formatter v1.3.1
	github.com/free5gc/openapi v1.0.4
	github.com/free5gc/util v1.0.1
	github.com/gin-contrib/cors v1.3.1
	github.com/gin-gonic/gin v1.7.3
	github.com/golang-jwt/jwt v3.2.1+incompatible
	github.com/google/uuid v1.3.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.8.1
	github.com/urfave/cli v1.22.5
	go.mongodb.org/mongo-driver v1.7.1
	golang.org/x/crypto v0.0.0-20201208171446-5f87f3452ae9
	gopkg.in/yaml.v2 v2.4.0
	github.com/free5gc/CDRUtil v0.0.0
)
replace github.com/free5gc/CDRUtil v0.0.0 => /home/uduck/CDRUtil
