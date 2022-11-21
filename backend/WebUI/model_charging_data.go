package WebUI

type ChargingData struct {
	OnlineCharging bool   `json:"onlineChargingChk,omitempty" yaml:"onlineChargingChk" bson:"onlineChargingChk" mapstructure:"onlineChargingChk"`
	Quota          int    `json:"quota,omitempty" yaml:"quota" bson:"quota" mapstructure:"quota"`
	UnitCost       string `json:"unitCost,omitempty" yaml:"unitCost" bson:"unitCost" mapstructure:"unitCost"`
}
