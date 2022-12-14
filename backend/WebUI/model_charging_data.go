package WebUI

import (
	"github.com/free5gc/TarrifUtil/tarrifType"
)

type ChargingData struct {
	OnlineCharging  bool                     `json:"onlineChargingChk,omitempty" yaml:"onlineChargingChk" bson:"onlineChargingChk" mapstructure:"onlineChargingChk"`
	OfflineCharging bool                     `json:"offlineChargingChk,omitempty" yaml:"offlineChargingChk" bson:"offlineChargingChk" mapstructure:"offlineChargingChk"`
	RatingGroup     int32                    `json:"ratingGroup,omitempty" yaml:"ratingGroup" bson:"ratingGroup" mapstructure:"ratingGroup"`
	Quota           uint32                   `json:"quota" yaml:"quota" bson:"quota" mapstructure:"quota"`
	UnitCost        string                   `json:"unitCost,omitempty" yaml:"unitCost" bson:"unitCost" mapstructure:"unitCost"`
	CurrentTariff   tarrifType.CurrentTariff `json:"tarrif,omitempty" bson:"tarrif"`
}
