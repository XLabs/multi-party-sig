// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.36.6
// 	protoc        v5.29.3
// source: proto/frost-keygen.proto

package keygen

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
	unsafe "unsafe"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// Represents Frost's keygen message 1.
type Broadcast2 struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// Phi_i is the commitment to the polynomial that this participant generated.
	// has a specific type to be unmarshalled into.:
	Phii []byte `protobuf:"bytes,1,opt,name=Phii,proto3" json:"Phii,omitempty"`
	// has a specific type to be unmarshalled into.
	// Sigma_i is the Schnorr proof of knowledge of the participant's secret.
	Sigmai []byte `protobuf:"bytes,2,opt,name=Sigmai,proto3" json:"Sigmai,omitempty"`
	// Commitment = H(cᵢ, uᵢ)
	// is byte slice.
	Commitment    []byte `protobuf:"bytes,3,opt,name=Commitment,proto3" json:"Commitment,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Broadcast2) Reset() {
	*x = Broadcast2{}
	mi := &file_proto_frost_keygen_proto_msgTypes[0]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Broadcast2) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Broadcast2) ProtoMessage() {}

func (x *Broadcast2) ProtoReflect() protoreflect.Message {
	mi := &file_proto_frost_keygen_proto_msgTypes[0]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Broadcast2.ProtoReflect.Descriptor instead.
func (*Broadcast2) Descriptor() ([]byte, []int) {
	return file_proto_frost_keygen_proto_rawDescGZIP(), []int{0}
}

func (x *Broadcast2) GetPhii() []byte {
	if x != nil {
		return x.Phii
	}
	return nil
}

func (x *Broadcast2) GetSigmai() []byte {
	if x != nil {
		return x.Sigmai
	}
	return nil
}

func (x *Broadcast2) GetCommitment() []byte {
	if x != nil {
		return x.Commitment
	}
	return nil
}

type Broadcast3 struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// C_l is contribution to the chaining key for this party.
	// is a byte slice.
	Cl []byte `protobuf:"bytes,1,opt,name=Cl,proto3" json:"Cl,omitempty"`
	// Decommitment = uᵢ decommitment bytes
	// is a byte slice.
	Decommitment  []byte `protobuf:"bytes,2,opt,name=Decommitment,proto3" json:"Decommitment,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Broadcast3) Reset() {
	*x = Broadcast3{}
	mi := &file_proto_frost_keygen_proto_msgTypes[1]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Broadcast3) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Broadcast3) ProtoMessage() {}

func (x *Broadcast3) ProtoReflect() protoreflect.Message {
	mi := &file_proto_frost_keygen_proto_msgTypes[1]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Broadcast3.ProtoReflect.Descriptor instead.
func (*Broadcast3) Descriptor() ([]byte, []int) {
	return file_proto_frost_keygen_proto_rawDescGZIP(), []int{1}
}

func (x *Broadcast3) GetCl() []byte {
	if x != nil {
		return x.Cl
	}
	return nil
}

func (x *Broadcast3) GetDecommitment() []byte {
	if x != nil {
		return x.Decommitment
	}
	return nil
}

type Message3 struct {
	state protoimpl.MessageState `protogen:"open.v1"`
	// F_li is the secret share sent from party l to this party.
	// Should be unmarshalled into a specific type.
	FLi           []byte `protobuf:"bytes,1,opt,name=F_li,json=FLi,proto3" json:"F_li,omitempty"`
	unknownFields protoimpl.UnknownFields
	sizeCache     protoimpl.SizeCache
}

func (x *Message3) Reset() {
	*x = Message3{}
	mi := &file_proto_frost_keygen_proto_msgTypes[2]
	ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
	ms.StoreMessageInfo(mi)
}

func (x *Message3) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Message3) ProtoMessage() {}

func (x *Message3) ProtoReflect() protoreflect.Message {
	mi := &file_proto_frost_keygen_proto_msgTypes[2]
	if x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Message3.ProtoReflect.Descriptor instead.
func (*Message3) Descriptor() ([]byte, []int) {
	return file_proto_frost_keygen_proto_rawDescGZIP(), []int{2}
}

func (x *Message3) GetFLi() []byte {
	if x != nil {
		return x.FLi
	}
	return nil
}

var File_proto_frost_keygen_proto protoreflect.FileDescriptor

const file_proto_frost_keygen_proto_rawDesc = "" +
	"\n" +
	"\x18proto/frost-keygen.proto\x12\x12xlabs.frost.keygen\"X\n" +
	"\n" +
	"Broadcast2\x12\x12\n" +
	"\x04Phii\x18\x01 \x01(\fR\x04Phii\x12\x16\n" +
	"\x06Sigmai\x18\x02 \x01(\fR\x06Sigmai\x12\x1e\n" +
	"\n" +
	"Commitment\x18\x03 \x01(\fR\n" +
	"Commitment\"@\n" +
	"\n" +
	"Broadcast3\x12\x0e\n" +
	"\x02Cl\x18\x01 \x01(\fR\x02Cl\x12\"\n" +
	"\fDecommitment\x18\x02 \x01(\fR\fDecommitment\"\x1d\n" +
	"\bMessage3\x12\x11\n" +
	"\x04F_li\x18\x01 \x01(\fR\x03FLiB\x18Z\x16protocols/frost/keygenb\x06proto3"

var (
	file_proto_frost_keygen_proto_rawDescOnce sync.Once
	file_proto_frost_keygen_proto_rawDescData []byte
)

func file_proto_frost_keygen_proto_rawDescGZIP() []byte {
	file_proto_frost_keygen_proto_rawDescOnce.Do(func() {
		file_proto_frost_keygen_proto_rawDescData = protoimpl.X.CompressGZIP(unsafe.Slice(unsafe.StringData(file_proto_frost_keygen_proto_rawDesc), len(file_proto_frost_keygen_proto_rawDesc)))
	})
	return file_proto_frost_keygen_proto_rawDescData
}

var file_proto_frost_keygen_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_proto_frost_keygen_proto_goTypes = []any{
	(*Broadcast2)(nil), // 0: xlabs.frost.keygen.Broadcast2
	(*Broadcast3)(nil), // 1: xlabs.frost.keygen.Broadcast3
	(*Message3)(nil),   // 2: xlabs.frost.keygen.Message3
}
var file_proto_frost_keygen_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_proto_frost_keygen_proto_init() }
func file_proto_frost_keygen_proto_init() {
	if File_proto_frost_keygen_proto != nil {
		return
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: unsafe.Slice(unsafe.StringData(file_proto_frost_keygen_proto_rawDesc), len(file_proto_frost_keygen_proto_rawDesc)),
			NumEnums:      0,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_frost_keygen_proto_goTypes,
		DependencyIndexes: file_proto_frost_keygen_proto_depIdxs,
		MessageInfos:      file_proto_frost_keygen_proto_msgTypes,
	}.Build()
	File_proto_frost_keygen_proto = out.File
	file_proto_frost_keygen_proto_goTypes = nil
	file_proto_frost_keygen_proto_depIdxs = nil
}
