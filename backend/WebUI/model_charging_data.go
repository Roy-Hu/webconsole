package WebUI

import (
	"github.com/free5gc/TarrifUtil/tarrifType"
)

type ChargingData struct {
	OnlineCharging bool                     `json:"onlineChargingChk,omitempty" yaml:"onlineChargingChk" bson:"onlineChargingChk" mapstructure:"onlineChargingChk"`
	Quota          uint32                  `json:"quota" yaml:"quota" bson:"quota" mapstructure:"quota"`
	UnitCost       string                   `json:"unitCost,omitempty" yaml:"unitCost" bson:"unitCost" mapstructure:"unitCost"`
	CurrentTariff  tarrifType.CurrentTariff `json:"tarrif,omitempty" bson:"tarrif"`
}
