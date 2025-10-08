package test

import common "github.com/xlabs/tss-common"

var TestTrackingID = &common.TrackingID{
	Digest:        []byte{1, 2, 3, 4},
	PartiesState:  nil,
	AuxiliaryData: nil,
	Protocol:      uint32(common.ProtocolFROSTSign.ToInt()), // just a placeholder
}
