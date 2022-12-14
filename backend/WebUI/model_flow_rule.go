package WebUI

type FlowRule struct {
	Filter       string       `json:"filter" yaml:"filter" bson:"filter" mapstructure:"filter"`
	Snssai       string       `json:"snssai,omitempty" yaml:"snssai" bson:"snssai" mapstructure:"snssai"`
	Dnn          string       `json:"dnn,omitempty" yaml:"v" bson:"dnn" mapstructure:"dnn"`
	Var5QI       int          `json:"5qi,omitempty" yaml:"5qi" bson:"5qi" mapstructure:"5qi"`
	MBRUL        string       `json:"mbrUL,omitempty" yaml:"mbrUL" bson:"mbrUL" mapstructure:"mbrUL"`
	MBRDL        string       `json:"mbrDL,omitempty" yaml:"mbrDL" bson:"mbrDL" mapstructure:"mbrDL"`
	GBRUL        string       `json:"gbrUL,omitempty" yaml:"gbrUL" bson:"gbrUL" mapstructure:"gbrUL"`
	GBRDL        string       `json:"gbrDL,omitempty" yaml:"gbrDL" bson:"gbrDL" mapstructure:"gbrDL"`
	ChargingData ChargingData `json:"charging,omitempty" yaml:"charging" bson:"charging" mapstructure:"charging"`
	RatingGroup  int32        `json:"ratingGroup,omitempty" yaml:"ratingGroup" bson:"ratingGroup" mapstructure:"ratingGroup"`
	Online       bool         `json:"onlineChargingChk" yaml:"Online" bson:"Online" mapstructure:"Online"`
	Offline      bool         `json:"offlineChargingChk" yaml:"Offline" bson:"Offline" mapstructure:"Offline"`
}
