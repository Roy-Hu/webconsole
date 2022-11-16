package WebUI

type URR struct {
	OnlineCharging bool `json:"onlineChargingChk,omitempty" yaml:"onlineChargingChk" bson:"onlineChargingChk" mapstructure:"onlineChargingChk"`
	Quota          int  `json:"quota,omitempty" yaml:"quota" bson:"quota" mapstructure:"quota"`
}
