package WebUI

import (
	"crypto/tls"
	// "encoding/binary"
	"encoding/json"
	"fmt"

	// "io/ioutil"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"go.mongodb.org/mongo-driver/bson"
	// "go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"

	"strconv"

	"github.com/free5gc/CDRUtil/asn"
	"github.com/free5gc/CDRUtil/cdrFile"
	"github.com/free5gc/CDRUtil/cdrType"
	"github.com/free5gc/TarrifUtil/tarrifType"
	"github.com/free5gc/openapi/models"
	"github.com/free5gc/util/mongoapi"
	"github.com/free5gc/webconsole/backend/logger"
	"github.com/free5gc/webconsole/backend/webui_context"
)

const (
	authSubsDataColl = "subscriptionData.authenticationData.authenticationSubscription"
	amDataColl       = "subscriptionData.provisionedData.amData"
	smDataColl       = "subscriptionData.provisionedData.smData"
	smfSelDataColl   = "subscriptionData.provisionedData.smfSelectionSubscriptionData"
	amPolicyDataColl = "policyData.ues.amData"
	smPolicyDataColl = "policyData.ues.smData"
	flowRuleDataColl = "policyData.ues.flowRule"
	userDataColl     = "userData"
	tenantDataColl   = "tenantData"
	quotaDataColl    = "quotaData"
	chargingDataColl = "chargingData"
)

var httpsClient *http.Client
var SupiRatingGroupIDMap map[string]uint32

func init() {
	httpsClient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	SupiRatingGroupIDMap = make(map[string]uint32)
	SupiRatingGroupIDMap["imsi-208930000000003"] = 1
}

func mapToByte(data map[string]interface{}) (ret []byte) {
	ret, _ = json.Marshal(data)
	return
}

func sliceToByte(data []map[string]interface{}) (ret []byte) {
	ret, _ = json.Marshal(data)
	return
}

func toBsonM(data interface{}) (ret bson.M) {
	tmp, _ := json.Marshal(data)
	json.Unmarshal(tmp, &ret)
	return
}

func toBsonA(data interface{}) (ret bson.A) {
	tmp, _ := json.Marshal(data)
	json.Unmarshal(tmp, &ret)
	return
}

func EscapeDnn(dnn string) string {
	return strings.ReplaceAll(dnn, ".", "_")
}

func UnescapeDnn(dnnKey string) string {
	return strings.ReplaceAll(dnnKey, "_", ".")
}

func setCorsHeader(c *gin.Context) {
	c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
	c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
	c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
	c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, PATCH, DELETE")
}

func sendResponseToClient(c *gin.Context, response *http.Response) {
	var jsonData interface{}
	json.NewDecoder(response.Body).Decode(&jsonData)
	c.JSON(response.StatusCode, jsonData)
}

func sendResponseToClientFilterTenant(c *gin.Context, response *http.Response, tenantId string) {
	// Subscription data.
	filterTenantIdOnly := bson.M{"tenantId": tenantId}
	amDataList, err := mongoapi.RestfulAPIGetMany(amDataColl, filterTenantIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("sendResponseToClientFilterTenant err: %+v", err)
	}

	tenantCheck := func(supi string) bool {
		for _, amData := range amDataList {
			if supi == amData["ueId"] {
				return true
			}
		}
		return false
	}

	// Response data.
	var jsonData interface{}
	json.NewDecoder(response.Body).Decode(&jsonData)

	s := reflect.ValueOf(jsonData)
	if s.Kind() != reflect.Slice {
		c.JSON(response.StatusCode, jsonData)
		return
	}

	var sliceData []interface{}
	for i := 0; i < s.Len(); i++ {
		mapData := s.Index(i).Interface()
		m := reflect.ValueOf(mapData)
		for _, key := range m.MapKeys() {
			if key.String() == "Supi" {
				strct := m.MapIndex(key)
				if tenantCheck(strct.Interface().(string)) {
					sliceData = append(sliceData, mapData)
				}
			}
		}
	}

	c.JSON(response.StatusCode, sliceData)
}

func GetSampleJSON(c *gin.Context) {
	setCorsHeader(c)

	logger.WebUILog.Infoln("Get a JSON Example")

	var subsData SubsData

	authSubsData := models.AuthenticationSubscription{
		AuthenticationManagementField: "8000",
		AuthenticationMethod:          "5G_AKA", // "5G_AKA", "EAP_AKA_PRIME"
		Milenage: &models.Milenage{
			Op: &models.Op{
				EncryptionAlgorithm: 0,
				EncryptionKey:       0,
				OpValue:             "c9e8763286b5b9ffbdf56e1297d0887b", // Required
			},
		},
		Opc: &models.Opc{
			EncryptionAlgorithm: 0,
			EncryptionKey:       0,
			OpcValue:            "981d464c7c52eb6e5036234984ad0bcf", // Required
		},
		PermanentKey: &models.PermanentKey{
			EncryptionAlgorithm: 0,
			EncryptionKey:       0,
			PermanentKeyValue:   "5122250214c33e723a5dd523fc145fc0", // Required
		},
		SequenceNumber: "16f3b3f70fc2",
	}

	amDataData := models.AccessAndMobilitySubscriptionData{
		Gpsis: []string{
			"msisdn-0900000000",
		},
		Nssai: &models.Nssai{
			DefaultSingleNssais: []models.Snssai{
				{
					Sd:  "010203",
					Sst: 1,
				},
				{
					Sd:  "112233",
					Sst: 1,
				},
			},
			SingleNssais: []models.Snssai{
				{
					Sd:  "010203",
					Sst: 1,
				},
				{
					Sd:  "112233",
					Sst: 1,
				},
			},
		},
		SubscribedUeAmbr: &models.AmbrRm{
			Downlink: "1000 Kbps",
			Uplink:   "1000 Kbps",
		},
	}

	smDataData := []models.SessionManagementSubscriptionData{
		{
			SingleNssai: &models.Snssai{
				Sst: 1,
				Sd:  "010203",
			},
			DnnConfigurations: map[string]models.DnnConfiguration{
				"internet": {
					PduSessionTypes: &models.PduSessionTypes{
						DefaultSessionType:  models.PduSessionType_IPV4,
						AllowedSessionTypes: []models.PduSessionType{models.PduSessionType_IPV4},
					},
					SscModes: &models.SscModes{
						DefaultSscMode:  models.SscMode__1,
						AllowedSscModes: []models.SscMode{models.SscMode__1},
					},
					SessionAmbr: &models.Ambr{
						Downlink: "1000 Kbps",
						Uplink:   "1000 Kbps",
					},
					Var5gQosProfile: &models.SubscribedDefaultQos{
						Var5qi: 9,
						Arp: &models.Arp{
							PriorityLevel: 8,
						},
						PriorityLevel: 8,
					},
				},
			},
		},
		{
			SingleNssai: &models.Snssai{
				Sst: 1,
				Sd:  "112233",
			},
			DnnConfigurations: map[string]models.DnnConfiguration{
				"internet": {
					PduSessionTypes: &models.PduSessionTypes{
						DefaultSessionType:  models.PduSessionType_IPV4,
						AllowedSessionTypes: []models.PduSessionType{models.PduSessionType_IPV4},
					},
					SscModes: &models.SscModes{
						DefaultSscMode:  models.SscMode__1,
						AllowedSscModes: []models.SscMode{models.SscMode__1},
					},
					SessionAmbr: &models.Ambr{
						Downlink: "1000 Kbps",
						Uplink:   "1000 Kbps",
					},
					Var5gQosProfile: &models.SubscribedDefaultQos{
						Var5qi: 9,
						Arp: &models.Arp{
							PriorityLevel: 8,
						},
						PriorityLevel: 8,
					},
				},
			},
		},
	}

	smfSelData := models.SmfSelectionSubscriptionData{
		SubscribedSnssaiInfos: map[string]models.SnssaiInfo{
			"01010203": {
				DnnInfos: []models.DnnInfo{
					{
						Dnn: "internet",
					},
				},
			},
			"01112233": {
				DnnInfos: []models.DnnInfo{
					{
						Dnn: "internet",
					},
				},
			},
		},
	}

	amPolicyData := models.AmPolicyData{
		SubscCats: []string{
			"free5gc",
		},
	}

	smPolicyData := models.SmPolicyData{
		SmPolicySnssaiData: map[string]models.SmPolicySnssaiData{
			"01010203": {
				Snssai: &models.Snssai{
					Sd:  "010203",
					Sst: 1,
				},
				SmPolicyDnnData: map[string]models.SmPolicyDnnData{
					"internet": {
						Dnn: "internet",
					},
				},
			},
			"01112233": {
				Snssai: &models.Snssai{
					Sd:  "112233",
					Sst: 1,
				},
				SmPolicyDnnData: map[string]models.SmPolicyDnnData{
					"internet": {
						Dnn: "internet",
					},
				},
			},
		},
	}

	servingPlmnId := "20893"
	ueId := "imsi-2089300007487"

	subsData = SubsData{
		PlmnID:                            servingPlmnId,
		UeId:                              ueId,
		AuthenticationSubscription:        authSubsData,
		AccessAndMobilitySubscriptionData: amDataData,
		SessionManagementSubscriptionData: smDataData,
		SmfSelectionSubscriptionData:      smfSelData,
		AmPolicyData:                      amPolicyData,
		SmPolicyData:                      smPolicyData,
	}
	c.JSON(http.StatusOK, subsData)
}

type OAuth struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func JWT(email, userId, tenantId string) string {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = userId
	claims["iat"] = time.Now()
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()
	claims["email"] = email
	claims["tenantId"] = tenantId

	tokenString, _ := token.SignedString([]byte(os.Getenv("SIGNINGKEY")))

	return tokenString
}

func generateHash(password string) {
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), 12)
	logger.WebUILog.Warnln("Password hash:", hash)
}

func Login(c *gin.Context) {
	setCorsHeader(c)

	login := LoginRequest{}
	err := json.NewDecoder(c.Request.Body).Decode(&login)
	if err != nil {
		logger.WebUILog.Warnln("JSON decode error", err)
		c.JSON(http.StatusInternalServerError, gin.H{})
		return
	}

	generateHash(login.Password)

	filterEmail := bson.M{"email": login.Username}
	userData, err := mongoapi.RestfulAPIGetOne(userDataColl, filterEmail)
	if err != nil {
		logger.WebUILog.Errorf("Login err: %+v", err)
	}

	if len(userData) == 0 {
		logger.WebUILog.Warnln("Can't find user email", login.Username)
		c.JSON(http.StatusForbidden, gin.H{})
		return
	}

	hash := userData["encryptedPassword"].(string)

	err = bcrypt.CompareHashAndPassword([]byte(hash), []byte(login.Password))
	if err != nil {
		logger.WebUILog.Warnln("Password incorrect", login.Username)
		c.JSON(http.StatusForbidden, gin.H{})
		return
	}

	userId := userData["userId"].(string)
	tenantId := userData["tenantId"].(string)

	logger.WebUILog.Warnln("Login success", login.Username)
	logger.WebUILog.Warnln("userid", userId)
	logger.WebUILog.Warnln("tenantid", tenantId)

	token := JWT(login.Username, userId, tenantId)
	logger.WebUILog.Warnln("token", token)

	oauth := OAuth{}
	oauth.AccessToken = token
	c.JSON(http.StatusOK, oauth)
}

// Placeholder to handle logout.
func Logout(c *gin.Context) {
	setCorsHeader(c)
	// Needs to invalidate access_token.
	c.JSON(http.StatusOK, gin.H{})
}

type AuthSub struct {
	models.AuthenticationSubscription
	TenantId string `json:"tenantId" bson:"tenantId"`
}

// Parse JWT
func ParseJWT(tokenStr string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("SIGNINGKEY")), nil
	})

	if err != nil {
		return nil, errors.Wrap(err, "ParseJWT error")
	}

	claims, _ := token.Claims.(jwt.MapClaims)

	return claims, nil
}

// Check of admin user. This should be done with proper JWT token.
func CheckAuth(c *gin.Context) bool {
	tokenStr := c.GetHeader("Token")
	if tokenStr == "admin" {
		return true
	} else {
		return false
	}
}

// Tenat ID
func GetTenantId(c *gin.Context) (string, error) {
	tokenStr := c.GetHeader("Token")
	if tokenStr == "admin" {
		return "", nil
	}
	claims, err := ParseJWT(tokenStr)
	if err != nil {
		return "", errors.Wrap(err, "GetTenantId error")
	}
	return claims["tenantId"].(string), nil
}

// Tenant
func GetTenants(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantDataInterface, err := mongoapi.RestfulAPIGetMany(tenantDataColl, bson.M{})
	if err != nil {
		logger.WebUILog.Errorf("GetTenants err: %+v", err)
	}
	var tenantData []Tenant
	json.Unmarshal(sliceToByte(tenantDataInterface), &tenantData)

	c.JSON(http.StatusOK, tenantData)
}

func GetTenantByID(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantId := c.Param("tenantId")

	filterTenantIdOnly := bson.M{"tenantId": tenantId}
	tenantDataInterface, err := mongoapi.RestfulAPIGetOne(tenantDataColl, filterTenantIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("GetTenantByID err: %+v", err)
	}
	if len(tenantDataInterface) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	var tenantData Tenant
	json.Unmarshal(mapToByte(tenantDataInterface), &tenantData)

	c.JSON(http.StatusOK, tenantData)
}

func PostTenant(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	var tenantData Tenant
	if err := c.ShouldBindJSON(&tenantData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{})
		return
	}

	if tenantData.TenantId == "" {
		tenantData.TenantId = uuid.Must(uuid.NewRandom()).String()
	}

	tenantBsonM := toBsonM(tenantData)
	filterTenantIdOnly := bson.M{"tenantId": tenantData.TenantId}
	if _, err := mongoapi.RestfulAPIPost(tenantDataColl, filterTenantIdOnly, tenantBsonM); err != nil {
		logger.WebUILog.Errorf("PostTenant err: %+v", err)
	}

	c.JSON(http.StatusOK, tenantData)
}

func PutTenantByID(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantId := c.Param("tenantId")

	filterTenantIdOnly := bson.M{"tenantId": tenantId}
	tenantDataInterface, err := mongoapi.RestfulAPIGetOne(tenantDataColl, filterTenantIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("PutTenantByID err: %+v", err)
	}
	if len(tenantDataInterface) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	var tenantData Tenant
	if err := c.ShouldBindJSON(&tenantData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{})
		return
	}
	tenantData.TenantId = tenantId

	tenantBsonM := toBsonM(tenantData)
	filterTenantIdOnly = bson.M{"tenantId": tenantId}
	if _, err := mongoapi.RestfulAPIPost(tenantDataColl, filterTenantIdOnly, tenantBsonM); err != nil {
		logger.WebUILog.Errorf("PutTenantByID err: %+v", err)
	}

	c.JSON(http.StatusOK, gin.H{})
}

func DeleteTenantByID(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantId := c.Param("tenantId")
	filterTenantIdOnly := bson.M{"tenantId": tenantId}

	if err := mongoapi.RestfulAPIDeleteMany(amDataColl, filterTenantIdOnly); err != nil {
		logger.WebUILog.Errorf("DeleteTenantByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteMany(userDataColl, filterTenantIdOnly); err != nil {
		logger.WebUILog.Errorf("DeleteTenantByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteOne(tenantDataColl, filterTenantIdOnly); err != nil {
		logger.WebUILog.Errorf("DeleteTenantByID err: %+v", err)
	}

	c.JSON(http.StatusOK, gin.H{})
}

// Utility function.
func GetTenantById(tenantId string) map[string]interface{} {
	filterTenantIdOnly := bson.M{"tenantId": tenantId}
	tenantData, err := mongoapi.RestfulAPIGetOne(tenantDataColl, filterTenantIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("GetTenantById err: %+v", err)
		return nil
	}
	return tenantData
}

// Users
func GetUsers(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantId := c.Param("tenantId")
	if len(GetTenantById(tenantId)) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	filterTenantIdOnly := bson.M{"tenantId": tenantId}
	userDataInterface, err := mongoapi.RestfulAPIGetMany(userDataColl, filterTenantIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("GetUsers err: %+v", err)
	}

	var userData []User
	json.Unmarshal(sliceToByte(userDataInterface), &userData)
	for pos := range userData {
		userData[pos].EncryptedPassword = ""
	}

	c.JSON(http.StatusOK, userData)
}

func GetUserByID(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantId := c.Param("tenantId")
	if len(GetTenantById(tenantId)) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}
	userId := c.Param("userId")

	filterUserIdOnly := bson.M{"tenantId": tenantId, "userId": userId}
	userDataInterface, err := mongoapi.RestfulAPIGetOne(userDataColl, filterUserIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("GetUserByID err: %+v", err)
	}
	if len(userDataInterface) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	var userData User
	json.Unmarshal(mapToByte(userDataInterface), &userData)
	userData.EncryptedPassword = ""

	c.JSON(http.StatusOK, userData)
}

func PostUserByID(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantId := c.Param("tenantId")
	if len(GetTenantById(tenantId)) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	var userData User
	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{})
		return
	}

	filterEmail := bson.M{"email": userData.Email}
	userWithEmailData, err := mongoapi.RestfulAPIGetOne(userDataColl, filterEmail)
	if err != nil {
		logger.WebUILog.Errorf("PostUserByID err: %+v", err)
	}
	if len(userWithEmailData) != 0 {
		logger.WebUILog.Warnln("Email already exists", userData.Email)
		c.JSON(http.StatusForbidden, gin.H{})
		return
	}

	userData.TenantId = tenantId
	userData.UserId = uuid.Must(uuid.NewRandom()).String()
	hash, _ := bcrypt.GenerateFromPassword([]byte(userData.EncryptedPassword), 12)
	userData.EncryptedPassword = string(hash)

	userBsonM := toBsonM(userData)
	filterUserIdOnly := bson.M{"tenantId": userData.TenantId, "userId": userData.UserId}
	if _, err := mongoapi.RestfulAPIPost(userDataColl, filterUserIdOnly, userBsonM); err != nil {
		logger.WebUILog.Errorf("PostUserByID err: %+v", err)
	}

	c.JSON(http.StatusOK, userData)
}

func PutUserByID(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantId := c.Param("tenantId")
	if len(GetTenantById(tenantId)) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}
	userId := c.Param("userId")

	var newUserData User
	if err := c.ShouldBindJSON(&newUserData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{})
		return
	}

	filterUserIdOnly := bson.M{"tenantId": tenantId, "userId": userId}
	userDataInterface, err := mongoapi.RestfulAPIGetOne(userDataColl, filterUserIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("PutUserByID err: %+v", err)
	}
	if len(userDataInterface) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	var userData User
	json.Unmarshal(mapToByte(userDataInterface), &userData)

	if newUserData.Email != "" && newUserData.Email != userData.Email {
		filterEmail := bson.M{"email": newUserData.Email}
		sameEmailInterface, err := mongoapi.RestfulAPIGetOne(userDataColl, filterEmail)
		if err != nil {
			logger.WebUILog.Errorf("PutUserByID err: %+v", err)
		}
		if len(sameEmailInterface) != 0 {
			c.JSON(http.StatusBadRequest, bson.M{})
			return
		}
		userData.Email = newUserData.Email
	}

	if newUserData.EncryptedPassword != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(newUserData.EncryptedPassword), 12)
		userData.EncryptedPassword = string(hash)
	}

	userBsonM := toBsonM(userData)
	if _, err := mongoapi.RestfulAPIPost(userDataColl, filterUserIdOnly, userBsonM); err != nil {
		logger.WebUILog.Errorf("PutUserByID err: %+v", err)
	}

	c.JSON(http.StatusOK, userData)
}

func DeleteUserByID(c *gin.Context) {
	setCorsHeader(c)

	if !CheckAuth(c) {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}

	tenantId := c.Param("tenantId")
	if len(GetTenantById(tenantId)) == 0 {
		c.JSON(http.StatusNotFound, bson.M{})
		return
	}
	userId := c.Param("userId")

	filterUserIdOnly := bson.M{"tenantId": tenantId, "userId": userId}
	if err := mongoapi.RestfulAPIDeleteOne(userDataColl, filterUserIdOnly); err != nil {
		logger.WebUILog.Errorf("DeleteUserByID err: %+v", err)
	}

	c.JSON(http.StatusOK, gin.H{})
}

// Get all subscribers list
func GetSubscribers(c *gin.Context) {
	setCorsHeader(c)

	logger.WebUILog.Infoln("Get All Subscribers List")

	tokenStr := c.GetHeader("Token")

	var claims jwt.MapClaims = nil
	var err error = nil
	if tokenStr != "admin" {
		claims, err = ParseJWT(tokenStr)
	}
	if err != nil {
		logger.WebUILog.Errorln(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"cause": "Illegal Token",
		})
		return
	}

	var subsList []SubsListIE = make([]SubsListIE, 0)
	amDataList, err := mongoapi.RestfulAPIGetMany(amDataColl, bson.M{})
	if err != nil {
		logger.WebUILog.Errorf("GetSubscribers err: %+v", err)
	}
	for _, amData := range amDataList {
		ueId := amData["ueId"]
		servingPlmnId := amData["servingPlmnId"]
		tenantId := amData["tenantId"]

		filterUeIdOnly := bson.M{"ueId": ueId}
		authSubsDataInterface, err := mongoapi.RestfulAPIGetOne(authSubsDataColl, filterUeIdOnly)
		if err != nil {
			logger.WebUILog.Errorf("GetSubscribers err: %+v", err)
		}

		var authSubsData AuthSub
		json.Unmarshal(mapToByte(authSubsDataInterface), &authSubsData)

		if tokenStr == "admin" || tenantId == claims["tenantId"].(string) {
			tmp := SubsListIE{
				PlmnID: servingPlmnId.(string),
				UeId:   ueId.(string),
			}
			subsList = append(subsList, tmp)
		}
	}
	c.JSON(http.StatusOK, subsList)
}

// Get subscriber by IMSI(ueId) and PlmnID(servingPlmnId)
func GetSubscriberByID(c *gin.Context) {
	setCorsHeader(c)

	logger.WebUILog.Infoln("Get One Subscriber Data")

	var subsData SubsData

	ueId := c.Param("ueId")
	servingPlmnId := c.Param("servingPlmnId")

	filterUeIdOnly := bson.M{"ueId": ueId}
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}

	authSubsDataInterface, err := mongoapi.RestfulAPIGetOne(authSubsDataColl, filterUeIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("GetSubscriberByID err: %+v", err)
	}
	amDataDataInterface, err := mongoapi.RestfulAPIGetOne(amDataColl, filter)
	if err != nil {
		logger.WebUILog.Errorf("GetSubscriberByID err: %+v", err)
	}
	smDataDataInterface, err := mongoapi.RestfulAPIGetMany(smDataColl, filter)
	if err != nil {
		logger.WebUILog.Errorf("GetSubscriberByID err: %+v", err)
	}
	smfSelDataInterface, err := mongoapi.RestfulAPIGetOne(smfSelDataColl, filter)
	if err != nil {
		logger.WebUILog.Errorf("GetSubscriberByID err: %+v", err)
	}
	amPolicyDataInterface, err := mongoapi.RestfulAPIGetOne(amPolicyDataColl, filterUeIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("GetSubscriberByID err: %+v", err)
	}
	smPolicyDataInterface, err := mongoapi.RestfulAPIGetOne(smPolicyDataColl, filterUeIdOnly)
	if err != nil {
		logger.WebUILog.Errorf("GetSubscriberByID err: %+v", err)
	}
	flowRuleDataInterface, err := mongoapi.RestfulAPIGetMany(flowRuleDataColl, filter)
	if err != nil {
		logger.WebUILog.Errorf("GetSubscriberByID err: %+v", err)
	}
	filterCharging := bson.M{"ueId": ueId, "ratingGroup": 1}
	chargingDataInterface, err := mongoapi.RestfulAPIGetMany(chargingDataColl, filterCharging)
	if err != nil {
		logger.WebUILog.Errorf("GetSubscriberByID err: %+v", err)
	}
	logger.WebUILog.Warnln("chargingDataInterface", chargingDataInterface)

	var authSubsData models.AuthenticationSubscription
	json.Unmarshal(mapToByte(authSubsDataInterface), &authSubsData)
	var amDataData models.AccessAndMobilitySubscriptionData
	json.Unmarshal(mapToByte(amDataDataInterface), &amDataData)
	var smDataData []models.SessionManagementSubscriptionData
	json.Unmarshal(sliceToByte(smDataDataInterface), &smDataData)
	var smfSelData models.SmfSelectionSubscriptionData
	json.Unmarshal(mapToByte(smfSelDataInterface), &smfSelData)
	var amPolicyData models.AmPolicyData
	json.Unmarshal(mapToByte(amPolicyDataInterface), &amPolicyData)
	var smPolicyData models.SmPolicyData
	json.Unmarshal(mapToByte(smPolicyDataInterface), &smPolicyData)
	var flowRules []FlowRule
	json.Unmarshal(sliceToByte(flowRuleDataInterface), &flowRules)
	var chargingData []ChargingData
	json.Unmarshal(sliceToByte(chargingDataInterface), &chargingData)

	for key, SnssaiData := range smPolicyData.SmPolicySnssaiData {
		tmpSmPolicyDnnData := make(map[string]models.SmPolicyDnnData)
		for escapedDnn, dnn := range SnssaiData.SmPolicyDnnData {
			dnnKey := UnescapeDnn(escapedDnn)
			tmpSmPolicyDnnData[dnnKey] = dnn
		}
		SnssaiData.SmPolicyDnnData = tmpSmPolicyDnnData
		smPolicyData.SmPolicySnssaiData[key] = SnssaiData
	}

	subsData = SubsData{
		PlmnID:                            servingPlmnId,
		UeId:                              ueId,
		AuthenticationSubscription:        authSubsData,
		AccessAndMobilitySubscriptionData: amDataData,
		SessionManagementSubscriptionData: smDataData,
		SmfSelectionSubscriptionData:      smfSelData,
		AmPolicyData:                      amPolicyData,
		SmPolicyData:                      smPolicyData,
		FlowRules:                         flowRules,
		ChargingData:                      chargingData,
	}

	c.JSON(http.StatusOK, subsData)
}

// Post subscriber by IMSI(ueId) and PlmnID(servingPlmnId)
func PostSubscriberByID(c *gin.Context) {
	setCorsHeader(c)
	logger.WebUILog.Infoln("Post One Subscriber Data")

	var claims jwt.MapClaims = nil
	var err error = nil
	tokenStr := c.GetHeader("Token")

	if tokenStr != "admin" {
		claims, err = ParseJWT(tokenStr)
	}
	if err != nil {
		logger.WebUILog.Errorln(err.Error())
		c.JSON(http.StatusBadRequest, gin.H{
			"cause": "Illegal Token",
		})
		return
	}

	var subsData SubsData
	if err := c.ShouldBindJSON(&subsData); err != nil {
		logger.WebUILog.Errorf("PostSubscriberByID err: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"cause": "JSON format incorrect",
		})
		return
	}

	ueId := c.Param("ueId")
	servingPlmnId := c.Param("servingPlmnId")

	filterUeIdOnly := bson.M{"ueId": ueId}
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}

	// Lookup same UE ID of other tenant's subscription.
	if claims != nil {
		authSubsDataInterface, err := mongoapi.RestfulAPIGetOne(authSubsDataColl, filterUeIdOnly)
		if err != nil {
			logger.WebUILog.Errorf("PostSubscriberByID err: %+v", err)
		}
		if len(authSubsDataInterface) > 0 {
			if authSubsDataInterface["tenantId"].(string) != claims["tenantId"].(string) {
				c.JSON(http.StatusUnprocessableEntity, gin.H{})
				return
			}
		}
	}

	authSubsBsonM := toBsonM(subsData.AuthenticationSubscription)
	authSubsBsonM["ueId"] = ueId
	if claims != nil {
		authSubsBsonM["tenantId"] = claims["tenantId"].(string)
	}
	amDataBsonM := toBsonM(subsData.AccessAndMobilitySubscriptionData)
	amDataBsonM["ueId"] = ueId
	amDataBsonM["servingPlmnId"] = servingPlmnId
	if claims != nil {
		amDataBsonM["tenantId"] = claims["tenantId"].(string)
	}

	smDatasBsonA := make([]interface{}, 0, len(subsData.SessionManagementSubscriptionData))
	for _, smSubsData := range subsData.SessionManagementSubscriptionData {
		smDataBsonM := toBsonM(smSubsData)
		smDataBsonM["ueId"] = ueId
		smDataBsonM["servingPlmnId"] = servingPlmnId
		smDatasBsonA = append(smDatasBsonA, smDataBsonM)
	}

	for key, SnssaiData := range subsData.SmPolicyData.SmPolicySnssaiData {
		tmpSmPolicyDnnData := make(map[string]models.SmPolicyDnnData)
		for dnnKey, dnn := range SnssaiData.SmPolicyDnnData {
			escapedDnn := EscapeDnn(dnnKey)
			tmpSmPolicyDnnData[escapedDnn] = dnn
		}
		SnssaiData.SmPolicyDnnData = tmpSmPolicyDnnData
		subsData.SmPolicyData.SmPolicySnssaiData[key] = SnssaiData
	}

	smfSelSubsBsonM := toBsonM(subsData.SmfSelectionSubscriptionData)
	smfSelSubsBsonM["ueId"] = ueId
	smfSelSubsBsonM["servingPlmnId"] = servingPlmnId
	amPolicyDataBsonM := toBsonM(subsData.AmPolicyData)
	amPolicyDataBsonM["ueId"] = ueId
	smPolicyDataBsonM := toBsonM(subsData.SmPolicyData)
	smPolicyDataBsonM["ueId"] = ueId

	flowRulesBsonA := make([]interface{}, 0, len(subsData.FlowRules))
	for _, flowRule := range subsData.FlowRules {
		flowRuleBsonM := toBsonM(flowRule)
		flowRuleBsonM["ueId"] = ueId
		flowRuleBsonM["servingPlmnId"] = servingPlmnId
		flowRulesBsonA = append(flowRulesBsonA, flowRuleBsonM)
	}

	if _, err := mongoapi.RestfulAPIPost(authSubsDataColl, filterUeIdOnly, authSubsBsonM); err != nil {
		logger.WebUILog.Errorf("PostSubscriberByID err: %+v", err)
	}
	if _, err := mongoapi.RestfulAPIPost(amDataColl, filter, amDataBsonM); err != nil {
		logger.WebUILog.Errorf("PostSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIPostMany(smDataColl, filter, smDatasBsonA); err != nil {
		logger.WebUILog.Errorf("PostSubscriberByID err: %+v", err)
	}
	if _, err := mongoapi.RestfulAPIPost(smfSelDataColl, filter, smfSelSubsBsonM); err != nil {
		logger.WebUILog.Errorf("PostSubscriberByID err: %+v", err)
	}
	if _, err := mongoapi.RestfulAPIPost(amPolicyDataColl, filterUeIdOnly, amPolicyDataBsonM); err != nil {
		logger.WebUILog.Errorf("PostSubscriberByID err: %+v", err)
	}
	if _, err := mongoapi.RestfulAPIPost(smPolicyDataColl, filterUeIdOnly, smPolicyDataBsonM); err != nil {
		logger.WebUILog.Errorf("PostSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIPostMany(flowRuleDataColl, filter, flowRulesBsonA); err != nil {
		logger.WebUILog.Errorf("PostSubscriberByID err: %+v", err)
	}

	c.JSON(http.StatusCreated, gin.H{})
}

// Put subscriber by IMSI(ueId) and PlmnID(servingPlmnId)
func PutSubscriberByID(c *gin.Context) {
	setCorsHeader(c)
	logger.WebUILog.Infoln("Put One Subscriber Data")

	var subsData SubsData
	if err := c.ShouldBindJSON(&subsData); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"cause": "JSON format incorrect",
		})
		return
	}

	ueId := c.Param("ueId")
	servingPlmnId := c.Param("servingPlmnId")

	filterUeIdOnly := bson.M{"ueId": ueId}
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}

	authSubsBsonM := toBsonM(subsData.AuthenticationSubscription)
	authSubsBsonM["ueId"] = ueId
	amDataBsonM := toBsonM(subsData.AccessAndMobilitySubscriptionData)
	amDataBsonM["ueId"] = ueId
	amDataBsonM["servingPlmnId"] = servingPlmnId

	// Replace all data with new one
	if err := mongoapi.RestfulAPIDeleteMany(smDataColl, filter); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	}
	for _, data := range subsData.SessionManagementSubscriptionData {
		smDataBsonM := toBsonM(data)
		smDataBsonM["ueId"] = ueId
		smDataBsonM["servingPlmnId"] = servingPlmnId
		filterSmData := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId, "snssai": data.SingleNssai}
		if _, err := mongoapi.RestfulAPIPutOne(smDataColl, filterSmData, smDataBsonM); err != nil {
			logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
		}
	}

	for key, SnssaiData := range subsData.SmPolicyData.SmPolicySnssaiData {
		tmpSmPolicyDnnData := make(map[string]models.SmPolicyDnnData)
		for dnnKey, dnn := range SnssaiData.SmPolicyDnnData {
			escapedDnn := EscapeDnn(dnnKey)
			tmpSmPolicyDnnData[escapedDnn] = dnn
		}
		SnssaiData.SmPolicyDnnData = tmpSmPolicyDnnData
		subsData.SmPolicyData.SmPolicySnssaiData[key] = SnssaiData
	}

	smfSelSubsBsonM := toBsonM(subsData.SmfSelectionSubscriptionData)
	smfSelSubsBsonM["ueId"] = ueId
	smfSelSubsBsonM["servingPlmnId"] = servingPlmnId
	amPolicyDataBsonM := toBsonM(subsData.AmPolicyData)
	amPolicyDataBsonM["ueId"] = ueId
	smPolicyDataBsonM := toBsonM(subsData.SmPolicyData)
	smPolicyDataBsonM["ueId"] = ueId

	flowRulesBsonA := make([]interface{}, 0, len(subsData.FlowRules))
	// chargingBsonA := make([]interface{}, 0, len(subsData.FlowRules))
	for _, flowRule := range subsData.FlowRules {
		flowRuleBsonM := toBsonM(flowRule)
		flowRuleBsonM["ueId"] = ueId
		flowRuleBsonM["servingPlmnId"] = servingPlmnId
		flowRuleBsonM["Online"] = flowRule.ChargingData.OnlineCharging
		flowRuleBsonM["Offline"] = flowRule.ChargingData.OfflineCharging
		// unitCost
		unitCost := tarrifType.UnitCost{}
		dotPos := strings.Index(flowRule.ChargingData.UnitCost, ".")
		if dotPos == -1 {
			unitCost.Exponent = 0
			if digit, err := strconv.Atoi(flowRule.ChargingData.UnitCost); err == nil {
				unitCost.ValueDigits = int64(digit)
			}
		} else {
			if digit, err := strconv.Atoi(strings.Replace(flowRule.ChargingData.UnitCost, ".", "", -1)); err == nil {
				unitCost.ValueDigits = int64(digit)
			}
			unitCost.Exponent = len(flowRule.ChargingData.UnitCost) - dotPos - 1
		}
		flowRuleBsonM["tarrif"] = tarrifType.CurrentTariff{
			RateElement: &tarrifType.RateElement{
				UnitCost: &unitCost,
				CCUnitType: &tarrifType.CCUnitType{
					Value: tarrifType.MONEY,
				},
			},
		}

		// chargingBsonM := primitive.M{
		// 	"ueId":        ueId,
		// 	"ratingGroup": flowRule.ChargingData.RatingGroup,
		// 	"tarrif": tarrifType.CurrentTariff{
		// 		RateElement: &tarrifType.RateElement{
		// 			UnitCost: &unitCost,
		// 			CCUnitType: &tarrifType.CCUnitType{
		// 				Value: tarrifType.MONEY,
		// 			},
		// 		},
		// 	},
		// }

		flowRulesBsonA = append(flowRulesBsonA, flowRuleBsonM)
		// chargingBsonA = append(chargingBsonA, chargingBsonM)
	}
	// Replace all data with new one
	if err := mongoapi.RestfulAPIDeleteMany(flowRuleDataColl, filter); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIPostMany(flowRuleDataColl, filter, flowRulesBsonA); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	}
	// if err := mongoapi.RestfulAPIDeleteMany(chargingDataColl, filterUeIdOnly); err != nil {
	// 	logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	// }
	// if err := mongoapi.RestfulAPIPostMany(chargingDataColl, filterUeIdOnly, chargingBsonA); err != nil {
	// 	logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	// }

	// charging: for default flow
	if subsData.ChargingData != nil && len(subsData.ChargingData) > 0 {
		urr := subsData.ChargingData[0]
		chargingBsonM := toBsonM(urr)

		chargingBsonM["ueId"] = ueId
		chargingBsonM["ratingGroup"] = 1

		// unitCost
		unitCost := tarrifType.UnitCost{}
		dotPos := strings.Index(urr.UnitCost, ".")
		if dotPos == -1 {
			unitCost.Exponent = 0
			if digit, err := strconv.Atoi(urr.UnitCost); err == nil {
				unitCost.ValueDigits = int64(digit)
			}
		} else {
			if digit, err := strconv.Atoi(strings.Replace(urr.UnitCost, ".", "", -1)); err == nil {
				unitCost.ValueDigits = int64(digit)
			}
			unitCost.Exponent = len(urr.UnitCost) - dotPos - 1
		}

		chargingBsonM["tarrif"] = tarrifType.CurrentTariff{
			RateElement: &tarrifType.RateElement{
				UnitCost: &unitCost,
				CCUnitType: &tarrifType.CCUnitType{
					Value: tarrifType.MONEY,
				},
			},
		}

		filterDefault := bson.M{"ueId": ueId, "ratingGroup": 1}
		if _, err := mongoapi.RestfulAPIPutOne(chargingDataColl, filterDefault, chargingBsonM); err != nil {
			logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
		}
	}

	if _, err := mongoapi.RestfulAPIPutOne(authSubsDataColl, filterUeIdOnly, authSubsBsonM); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	}
	if _, err := mongoapi.RestfulAPIPutOne(amDataColl, filter, amDataBsonM); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	}
	if _, err := mongoapi.RestfulAPIPutOne(smfSelDataColl, filter, smfSelSubsBsonM); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	}
	if _, err := mongoapi.RestfulAPIPutOne(amPolicyDataColl, filterUeIdOnly, amPolicyDataBsonM); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	}
	if _, err := mongoapi.RestfulAPIPutOne(smPolicyDataColl, filterUeIdOnly, smPolicyDataBsonM); err != nil {
		logger.WebUILog.Errorf("PutSubscriberByID err: %+v", err)
	}

	c.JSON(http.StatusNoContent, gin.H{})
}

// Patch subscriber by IMSI(ueId) and PlmnID(servingPlmnId)
func PatchSubscriberByID(c *gin.Context) {
	setCorsHeader(c)
	logger.WebUILog.Infoln("Patch One Subscriber Data")

	var subsData SubsData
	if err := c.ShouldBindJSON(&subsData); err != nil {
		logger.WebUILog.Errorf("PatchSubscriberByID err: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"cause": "JSON format incorrect",
		})
		return
	}

	ueId := c.Param("ueId")
	servingPlmnId := c.Param("servingPlmnId")

	filterUeIdOnly := bson.M{"ueId": ueId}
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}

	authSubsBsonM := toBsonM(subsData.AuthenticationSubscription)
	authSubsBsonM["ueId"] = ueId
	amDataBsonM := toBsonM(subsData.AccessAndMobilitySubscriptionData)
	amDataBsonM["ueId"] = ueId
	amDataBsonM["servingPlmnId"] = servingPlmnId

	// Replace all data with new one
	if err := mongoapi.RestfulAPIDeleteMany(smDataColl, filter); err != nil {
		logger.WebUILog.Errorf("PatchSubscriberByID err: %+v", err)
	}
	for _, data := range subsData.SessionManagementSubscriptionData {
		smDataBsonM := toBsonM(data)
		smDataBsonM["ueId"] = ueId
		smDataBsonM["servingPlmnId"] = servingPlmnId
		filterSmData := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId, "snssai": data.SingleNssai}
		if err := mongoapi.RestfulAPIMergePatch(smDataColl, filterSmData, smDataBsonM); err != nil {
			logger.WebUILog.Errorf("PatchSubscriberByID err: %+v", err)
		}
	}

	for key, SnssaiData := range subsData.SmPolicyData.SmPolicySnssaiData {
		tmpSmPolicyDnnData := make(map[string]models.SmPolicyDnnData)
		for dnnKey, dnn := range SnssaiData.SmPolicyDnnData {
			escapedDnn := EscapeDnn(dnnKey)
			tmpSmPolicyDnnData[escapedDnn] = dnn
		}
		SnssaiData.SmPolicyDnnData = tmpSmPolicyDnnData
		subsData.SmPolicyData.SmPolicySnssaiData[key] = SnssaiData
	}

	smfSelSubsBsonM := toBsonM(subsData.SmfSelectionSubscriptionData)
	smfSelSubsBsonM["ueId"] = ueId
	smfSelSubsBsonM["servingPlmnId"] = servingPlmnId
	amPolicyDataBsonM := toBsonM(subsData.AmPolicyData)
	amPolicyDataBsonM["ueId"] = ueId
	smPolicyDataBsonM := toBsonM(subsData.SmPolicyData)
	smPolicyDataBsonM["ueId"] = ueId

	if err := mongoapi.RestfulAPIMergePatch(authSubsDataColl, filterUeIdOnly, authSubsBsonM); err != nil {
		logger.WebUILog.Errorf("PatchSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIMergePatch(amDataColl, filter, amDataBsonM); err != nil {
		logger.WebUILog.Errorf("PatchSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIMergePatch(smfSelDataColl, filter, smfSelSubsBsonM); err != nil {
		logger.WebUILog.Errorf("PatchSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIMergePatch(amPolicyDataColl, filterUeIdOnly, amPolicyDataBsonM); err != nil {
		logger.WebUILog.Errorf("PatchSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIMergePatch(smPolicyDataColl, filterUeIdOnly, smPolicyDataBsonM); err != nil {
		logger.WebUILog.Errorf("PatchSubscriberByID err: %+v", err)
	}

	c.JSON(http.StatusNoContent, gin.H{})
}

// Delete subscriber by IMSI(ueId) and PlmnID(servingPlmnId)
func DeleteSubscriberByID(c *gin.Context) {
	setCorsHeader(c)
	logger.WebUILog.Infoln("Delete One Subscriber Data")

	ueId := c.Param("ueId")
	servingPlmnId := c.Param("servingPlmnId")

	filterUeIdOnly := bson.M{"ueId": ueId}
	filter := bson.M{"ueId": ueId, "servingPlmnId": servingPlmnId}

	if err := mongoapi.RestfulAPIDeleteOne(authSubsDataColl, filterUeIdOnly); err != nil {
		logger.WebUILog.Errorf("DeleteSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteOne(amDataColl, filter); err != nil {
		logger.WebUILog.Errorf("DeleteSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteMany(smDataColl, filter); err != nil {
		logger.WebUILog.Errorf("DeleteSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteMany(flowRuleDataColl, filter); err != nil {
		logger.WebUILog.Errorf("DeleteSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteOne(smfSelDataColl, filter); err != nil {
		logger.WebUILog.Errorf("DeleteSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteOne(amPolicyDataColl, filterUeIdOnly); err != nil {
		logger.WebUILog.Errorf("DeleteSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteOne(smPolicyDataColl, filterUeIdOnly); err != nil {
		logger.WebUILog.Errorf("DeleteSubscriberByID err: %+v", err)
	}
	if err := mongoapi.RestfulAPIDeleteMany(chargingDataColl, filterUeIdOnly); err != nil {
		logger.WebUILog.Errorf("DeleteSubscriberByID err: %+v", err)
	}

	c.JSON(http.StatusNoContent, gin.H{})
}

// util function
func getQuotaBySupi(supi string) uint32 {
	filter := bson.M{"ueId": supi, "ratingGroup": 1}
	chargingDataInterface, err := mongoapi.RestfulAPIGetMany(chargingDataColl, filter)
	if err != nil {
		logger.WebUILog.Errorf("getQuotaBySupi err: %+v", err)
	}
	var chargingData []ChargingData
	json.Unmarshal(sliceToByte(chargingDataInterface), &chargingData)

	if len(chargingData) > 0 {
		return uint32(chargingData[0].Quota)
	} else {
		return 0
	}
}

// for recharge
func GetQuotaByID(c *gin.Context) {
	setCorsHeader(c)

	logger.WebUILog.Infoln("Get Quota")

	supi, _ := c.Params.Get("supi")

	quota := getQuotaBySupi(supi)

	c.JSON(http.StatusOK, gin.H{
		"supi":  supi,
		"quota": quota,
	})
}

// for recharge
func PutQuotaByID(c *gin.Context) {
	setCorsHeader(c)
	logger.WebUILog.Infoln("Put Quota Data by ID")

	var quotaData QuotaData

	if err := c.ShouldBindJSON(&quotaData); err != nil {
		logger.WebUILog.Errorf("PutQuotaByID err: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"cause": "JSON format incorrect",
		})
		return
	}
	supi := c.Param("supi")

	filterDefault := bson.M{"ueId": supi, "ratingGroup": 1}
	chargingDataInterface, err := mongoapi.RestfulAPIGetMany(chargingDataColl, filterDefault)
	if err != nil {
		logger.WebUILog.Errorf("PutQuotaByID err: %+v", err)
	}

	var chargingData []ChargingData
	json.Unmarshal(sliceToByte(chargingDataInterface), &chargingData)

	logger.WebUILog.Warnln("chargingData: ", chargingData)

	if len(chargingData) > 0 {
		chargingBsonM := toBsonM(chargingData[0])
		if !chargingData[0].OnlineCharging {
			chargingBsonM["ratingGroup"] = 1
			chargingBsonM["onlineChargingChk"] = false
			chargingBsonM["quota"] = uint32(0)
			chargingBsonM["unitCost"] = ""
		}
		chargingBsonM["quota"] = uint32(quotaData.Quota)
		chargingBsonM["ratingGroup"] = 1

		logger.WebUILog.Warnln("chargingBsonM", chargingBsonM)

		if _, err := mongoapi.RestfulAPIPutOne(chargingDataColl, filterDefault, chargingBsonM); err != nil {
			logger.WebUILog.Errorf("PutQuotaByID err: %+v", err)
		}
	}

	// call recharge server
	webuiSelf := webui_context.WEBUI_Self()
	webuiSelf.UpdateNfProfiles()

	requestUri := fmt.Sprintf("%s/nchf-convergedcharging/v3/recharging/%s", "http://127.0.0.113:8000", supi)
	req, err := http.NewRequest(http.MethodPut, requestUri, nil)
	if err != nil {
		logger.WebUILog.Error(err)
	}
	req.Header.Add("Content-Type", "application/json")

	if _, err = http.DefaultClient.Do(req); err != nil {
		logger.WebUILog.Errorf("PutQuotaByID err: %+v", err)
	}

	c.JSON(http.StatusNoContent, gin.H{})
}

func GetRegisteredUEContext(c *gin.Context) {
	setCorsHeader(c)

	logger.WebUILog.Infoln("Get Registered UE Context")

	webuiSelf := webui_context.WEBUI_Self()
	webuiSelf.UpdateNfProfiles()

	supi, supiExists := c.Params.Get("supi")

	// TODO: support fetching data from multiple AMFs
	if amfUris := webuiSelf.GetOamUris(models.NfType_AMF); amfUris != nil {
		var requestUri string

		if supiExists {
			requestUri = fmt.Sprintf("%s/namf-oam/v1/registered-ue-context/%s", amfUris[0], supi)
		} else {
			requestUri = fmt.Sprintf("%s/namf-oam/v1/registered-ue-context", amfUris[0])
		}

		resp, err := httpsClient.Get(requestUri)
		if err != nil {
			logger.WebUILog.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{})
			return
		}

		// Filter by tenant.
		tenantId, err := GetTenantId(c)
		if err != nil {
			logger.WebUILog.Errorln(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"cause": "Illegal Token",
			})
			return
		}

		if tenantId == "" {
			sendResponseToClient(c, resp)
		} else {
			sendResponseToClientFilterTenant(c, resp, tenantId)
		}
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{
			"cause": "No AMF Found",
		})
	}
}

func GetUEPDUSessionInfo(c *gin.Context) {
	setCorsHeader(c)

	logger.WebUILog.Infoln("Get UE PDU Session Info")

	webuiSelf := webui_context.WEBUI_Self()
	webuiSelf.UpdateNfProfiles()

	smContextRef, smContextRefExists := c.Params.Get("smContextRef")
	if !smContextRefExists {
		c.JSON(http.StatusBadRequest, gin.H{})
		return
	}

	// TODO: support fetching data from multiple SMF
	if smfUris := webuiSelf.GetOamUris(models.NfType_SMF); smfUris != nil {
		requestUri := fmt.Sprintf("%s/nsmf-oam/v1/ue-pdu-session-info/%s", smfUris[0], smContextRef)
		resp, err := httpsClient.Get(requestUri)
		if err != nil {
			logger.WebUILog.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{})
			return
		}

		sendResponseToClient(c, resp)
	} else {
		c.JSON(http.StatusInternalServerError, gin.H{
			"cause": "No SMF Found",
		})
	}
}

// Get vol from CDR
func parseCDR(supi string) (totalVol int64, ulVol int64, dlVol int64) {
	fileName := "/tmp/webconsole/" + supi + ".cdr"
	cdr, err := os.ReadFile(fileName)
	if err != nil {
		logger.WebUILog.Warn("Fail to retrv file: ", fileName)
		return 0, 0, 0
	}

	logger.WebUILog.Warn("Retr CDR success")
	newCdrFile := cdrFile.CDRFile{}

	newCdrFile.DecodingBytes(cdr)
	logger.WebUILog.Warn("Decode CDR success")

	logger.WebUILog.Warn("Decode CDR success")
	logger.WebUILog.Warn("newCdrFile.CdrList len: ", len(newCdrFile.CdrList))

	for _, cdr := range newCdrFile.CdrList {
		recvByte := cdr.CdrByte
	
		val := reflect.New(reflect.TypeOf(&cdrType.ChargingRecord{}).Elem()).Interface()
		asn.UnmarshalWithParams(recvByte, val, "")
	
		chargingRecord := *(val.(*cdrType.ChargingRecord))
	
		for _, multipleUnitUsage := range chargingRecord.ListOfMultipleUnitUsage {
			// fmt.Println("rating group id", multipleUnitUsage.RatingGroup.Value)
			for _, usedUnitContainer := range multipleUnitUsage.UsedUnitContainers {
				totalVol += usedUnitContainer.DataTotalVolume.Value
				ulVol += usedUnitContainer.DataVolumeUplink.Value
				dlVol += usedUnitContainer.DataVolumeDownlink.Value
			}
		}
	}

	return totalVol, ulVol, dlVol
}

func GetChargingRecord(c *gin.Context) {
	setCorsHeader(c)

	if tokenStr := c.GetHeader("Token"); tokenStr != "admin" {
		if _, err := ParseJWT(tokenStr); err != nil {
			logger.WebUILog.Errorln(err.Error())
			c.JSON(http.StatusBadRequest, gin.H{
				"cause": "Illegal Token",
			})
			return
		}
	}

	webuiSelf := webui_context.WEBUI_Self()
	webuiSelf.UpdateNfProfiles()

	// Get supi of UEs
	var uesJsonData interface{}
	if amfUris := webuiSelf.GetOamUris(models.NfType_AMF); amfUris != nil {
		requestUri := fmt.Sprintf("%s/namf-oam/v1/registered-ue-context", amfUris[0])

		resp, err := httpsClient.Get(requestUri)
		if err != nil {
			logger.WebUILog.Error(err)
			c.JSON(http.StatusInternalServerError, gin.H{})
			return
		}

		json.NewDecoder(resp.Body).Decode(&uesJsonData)
	}

	// build charging records
	uesBsonA := toBsonA(uesJsonData)
	chargingRecordsBsonA := make([]interface{}, 0, len(uesBsonA))

	for _, ueData := range uesBsonA {
		ueBsonM := toBsonM(ueData)
		supi := ueBsonM["Supi"].(string)
		totalVol, ulVol, dlVol := parseCDR(supi)

		chargingRecordsBsonA = append(chargingRecordsBsonA, bson.M{
			"Supi":               supi,
			"CmState":            ueBsonM["CmState"].(string),
			"DataTotalVolume":    totalVol,
			"DataVolumeUplink":   ulVol,
			"DataVolumeDownlink": dlVol,
			"quotaLeft":          int32(getQuotaBySupi(supi)),
		})
	}

	c.JSON(http.StatusOK, chargingRecordsBsonA)
}
