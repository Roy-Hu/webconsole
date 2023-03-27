package WebUI

import (
	"github.com/free5gc/TarrifUtil/tarrifType"
)

type ChargingData struct {
	ChargingMethod string                   `json:"chargingMethod,omitempty" yaml:"chargingMethod" bson:"chargingMethod" mapstructure:"chargingMethod"`
	RatingGroup    int32                    `json:"ratingGroup,omitempty" yaml:"ratingGroup" bson:"ratingGroup" mapstructure:"ratingGroup"`
	Quota          uint32                   `json:"quota" yaml:"quota" bson:"quota" mapstructure:"quota"`
	UnitCost       string                   `json:"unitCost,omitempty" yaml:"unitCost" bson:"unitCost" mapstructure:"unitCost"`
	CurrentTariff  tarrifType.CurrentTariff `json:"tarrif,omitempty" bson:"tarrif"`
	Default        bool                     `json:"default" yaml:"default" bson:"default" mapstructure:"default"`
}
