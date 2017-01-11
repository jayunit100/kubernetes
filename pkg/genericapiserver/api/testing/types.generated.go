/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// ************************************************************
// DO NOT EDIT.
// THIS FILE IS AUTO-GENERATED BY codecgen.
// ************************************************************

package testing

import (
	"errors"
	"fmt"
	codec1978 "github.com/ugorji/go/codec"
	pkg1_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	pkg3_types "k8s.io/apimachinery/pkg/types"
	pkg2_v1 "k8s.io/kubernetes/pkg/api/v1"
	"reflect"
	"runtime"
	time "time"
)

const (
	// ----- content types ----
	codecSelferC_UTF81234 = 1
	codecSelferC_RAW1234  = 0
	// ----- value types used ----
	codecSelferValueTypeArray1234 = 10
	codecSelferValueTypeMap1234   = 9
	// ----- containerStateValues ----
	codecSelfer_containerMapKey1234    = 2
	codecSelfer_containerMapValue1234  = 3
	codecSelfer_containerMapEnd1234    = 4
	codecSelfer_containerArrayElem1234 = 6
	codecSelfer_containerArrayEnd1234  = 7
)

var (
	codecSelferBitsize1234                         = uint8(reflect.TypeOf(uint(0)).Bits())
	codecSelferOnlyMapOrArrayEncodeToStructErr1234 = errors.New(`only encoded map or array can be decoded into a struct`)
)

type codecSelfer1234 struct{}

func init() {
	if codec1978.GenVersion != 5 {
		_, file, _, _ := runtime.Caller(0)
		err := fmt.Errorf("codecgen version mismatch: current: %v, need %v. Re-generate file: %v",
			5, codec1978.GenVersion, file)
		panic(err)
	}
	if false { // reference the types, but skip this branch at build/run time
		var v0 pkg1_v1.TypeMeta
		var v1 pkg3_types.UID
		var v2 pkg2_v1.ObjectMeta
		var v3 time.Time
		_, _, _, _ = v0, v1, v2, v3
	}
}

func (x *Simple) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym1 := z.EncBinary()
		_ = yym1
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep2 := !z.EncBinary()
			yy2arr2 := z.EncBasicHandle().StructToArray
			var yyq2 [5]bool
			_, _, _ = yysep2, yyq2, yy2arr2
			const yyr2 bool = false
			yyq2[0] = x.Kind != ""
			yyq2[1] = x.APIVersion != ""
			yyq2[3] = x.Other != ""
			yyq2[4] = len(x.Labels) != 0
			var yynn2 int
			if yyr2 || yy2arr2 {
				r.EncodeArrayStart(5)
			} else {
				yynn2 = 1
				for _, b := range yyq2 {
					if b {
						yynn2++
					}
				}
				r.EncodeMapStart(yynn2)
				yynn2 = 0
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[0] {
					yym4 := z.EncBinary()
					_ = yym4
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq2[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("kind"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym5 := z.EncBinary()
					_ = yym5
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[1] {
					yym7 := z.EncBinary()
					_ = yym7
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq2[1] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("apiVersion"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym8 := z.EncBinary()
					_ = yym8
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yy10 := &x.ObjectMeta
				yy10.CodecEncodeSelf(e)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("metadata"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yy11 := &x.ObjectMeta
				yy11.CodecEncodeSelf(e)
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[3] {
					yym13 := z.EncBinary()
					_ = yym13
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Other))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq2[3] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("other"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym14 := z.EncBinary()
					_ = yym14
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Other))
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq2[4] {
					if x.Labels == nil {
						r.EncodeNil()
					} else {
						yym16 := z.EncBinary()
						_ = yym16
						if false {
						} else {
							z.F.EncMapStringStringV(x.Labels, false, e)
						}
					}
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq2[4] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("labels"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					if x.Labels == nil {
						r.EncodeNil()
					} else {
						yym17 := z.EncBinary()
						_ = yym17
						if false {
						} else {
							z.F.EncMapStringStringV(x.Labels, false, e)
						}
					}
				}
			}
			if yyr2 || yy2arr2 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *Simple) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym18 := z.DecBinary()
	_ = yym18
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct19 := r.ContainerType()
		if yyct19 == codecSelferValueTypeMap1234 {
			yyl19 := r.ReadMapStart()
			if yyl19 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl19, d)
			}
		} else if yyct19 == codecSelferValueTypeArray1234 {
			yyl19 := r.ReadArrayStart()
			if yyl19 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl19, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *Simple) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys20Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys20Slc
	var yyhl20 bool = l >= 0
	for yyj20 := 0; ; yyj20++ {
		if yyhl20 {
			if yyj20 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys20Slc = r.DecodeBytes(yys20Slc, true, true)
		yys20 := string(yys20Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys20 {
		case "kind":
			if r.TryDecodeAsNil() {
				x.Kind = ""
			} else {
				x.Kind = string(r.DecodeString())
			}
		case "apiVersion":
			if r.TryDecodeAsNil() {
				x.APIVersion = ""
			} else {
				x.APIVersion = string(r.DecodeString())
			}
		case "metadata":
			if r.TryDecodeAsNil() {
				x.ObjectMeta = pkg2_v1.ObjectMeta{}
			} else {
				yyv23 := &x.ObjectMeta
				yyv23.CodecDecodeSelf(d)
			}
		case "other":
			if r.TryDecodeAsNil() {
				x.Other = ""
			} else {
				x.Other = string(r.DecodeString())
			}
		case "labels":
			if r.TryDecodeAsNil() {
				x.Labels = nil
			} else {
				yyv25 := &x.Labels
				yym26 := z.DecBinary()
				_ = yym26
				if false {
				} else {
					z.F.DecMapStringStringX(yyv25, false, d)
				}
			}
		default:
			z.DecStructFieldNotFound(-1, yys20)
		} // end switch yys20
	} // end for yyj20
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *Simple) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj27 int
	var yyb27 bool
	var yyhl27 bool = l >= 0
	yyj27++
	if yyhl27 {
		yyb27 = yyj27 > l
	} else {
		yyb27 = r.CheckBreak()
	}
	if yyb27 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Kind = ""
	} else {
		x.Kind = string(r.DecodeString())
	}
	yyj27++
	if yyhl27 {
		yyb27 = yyj27 > l
	} else {
		yyb27 = r.CheckBreak()
	}
	if yyb27 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.APIVersion = ""
	} else {
		x.APIVersion = string(r.DecodeString())
	}
	yyj27++
	if yyhl27 {
		yyb27 = yyj27 > l
	} else {
		yyb27 = r.CheckBreak()
	}
	if yyb27 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.ObjectMeta = pkg2_v1.ObjectMeta{}
	} else {
		yyv30 := &x.ObjectMeta
		yyv30.CodecDecodeSelf(d)
	}
	yyj27++
	if yyhl27 {
		yyb27 = yyj27 > l
	} else {
		yyb27 = r.CheckBreak()
	}
	if yyb27 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Other = ""
	} else {
		x.Other = string(r.DecodeString())
	}
	yyj27++
	if yyhl27 {
		yyb27 = yyj27 > l
	} else {
		yyb27 = r.CheckBreak()
	}
	if yyb27 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Labels = nil
	} else {
		yyv32 := &x.Labels
		yym33 := z.DecBinary()
		_ = yym33
		if false {
		} else {
			z.F.DecMapStringStringX(yyv32, false, d)
		}
	}
	for {
		yyj27++
		if yyhl27 {
			yyb27 = yyj27 > l
		} else {
			yyb27 = r.CheckBreak()
		}
		if yyb27 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj27-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x *SimpleRoot) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym34 := z.EncBinary()
		_ = yym34
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep35 := !z.EncBinary()
			yy2arr35 := z.EncBasicHandle().StructToArray
			var yyq35 [5]bool
			_, _, _ = yysep35, yyq35, yy2arr35
			const yyr35 bool = false
			yyq35[0] = x.Kind != ""
			yyq35[1] = x.APIVersion != ""
			yyq35[3] = x.Other != ""
			yyq35[4] = len(x.Labels) != 0
			var yynn35 int
			if yyr35 || yy2arr35 {
				r.EncodeArrayStart(5)
			} else {
				yynn35 = 1
				for _, b := range yyq35 {
					if b {
						yynn35++
					}
				}
				r.EncodeMapStart(yynn35)
				yynn35 = 0
			}
			if yyr35 || yy2arr35 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq35[0] {
					yym37 := z.EncBinary()
					_ = yym37
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq35[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("kind"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym38 := z.EncBinary()
					_ = yym38
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				}
			}
			if yyr35 || yy2arr35 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq35[1] {
					yym40 := z.EncBinary()
					_ = yym40
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq35[1] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("apiVersion"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym41 := z.EncBinary()
					_ = yym41
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				}
			}
			if yyr35 || yy2arr35 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yy43 := &x.ObjectMeta
				yy43.CodecEncodeSelf(e)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("metadata"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yy44 := &x.ObjectMeta
				yy44.CodecEncodeSelf(e)
			}
			if yyr35 || yy2arr35 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq35[3] {
					yym46 := z.EncBinary()
					_ = yym46
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Other))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq35[3] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("other"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym47 := z.EncBinary()
					_ = yym47
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Other))
					}
				}
			}
			if yyr35 || yy2arr35 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq35[4] {
					if x.Labels == nil {
						r.EncodeNil()
					} else {
						yym49 := z.EncBinary()
						_ = yym49
						if false {
						} else {
							z.F.EncMapStringStringV(x.Labels, false, e)
						}
					}
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq35[4] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("labels"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					if x.Labels == nil {
						r.EncodeNil()
					} else {
						yym50 := z.EncBinary()
						_ = yym50
						if false {
						} else {
							z.F.EncMapStringStringV(x.Labels, false, e)
						}
					}
				}
			}
			if yyr35 || yy2arr35 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *SimpleRoot) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym51 := z.DecBinary()
	_ = yym51
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct52 := r.ContainerType()
		if yyct52 == codecSelferValueTypeMap1234 {
			yyl52 := r.ReadMapStart()
			if yyl52 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl52, d)
			}
		} else if yyct52 == codecSelferValueTypeArray1234 {
			yyl52 := r.ReadArrayStart()
			if yyl52 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl52, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *SimpleRoot) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys53Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys53Slc
	var yyhl53 bool = l >= 0
	for yyj53 := 0; ; yyj53++ {
		if yyhl53 {
			if yyj53 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys53Slc = r.DecodeBytes(yys53Slc, true, true)
		yys53 := string(yys53Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys53 {
		case "kind":
			if r.TryDecodeAsNil() {
				x.Kind = ""
			} else {
				x.Kind = string(r.DecodeString())
			}
		case "apiVersion":
			if r.TryDecodeAsNil() {
				x.APIVersion = ""
			} else {
				x.APIVersion = string(r.DecodeString())
			}
		case "metadata":
			if r.TryDecodeAsNil() {
				x.ObjectMeta = pkg2_v1.ObjectMeta{}
			} else {
				yyv56 := &x.ObjectMeta
				yyv56.CodecDecodeSelf(d)
			}
		case "other":
			if r.TryDecodeAsNil() {
				x.Other = ""
			} else {
				x.Other = string(r.DecodeString())
			}
		case "labels":
			if r.TryDecodeAsNil() {
				x.Labels = nil
			} else {
				yyv58 := &x.Labels
				yym59 := z.DecBinary()
				_ = yym59
				if false {
				} else {
					z.F.DecMapStringStringX(yyv58, false, d)
				}
			}
		default:
			z.DecStructFieldNotFound(-1, yys53)
		} // end switch yys53
	} // end for yyj53
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *SimpleRoot) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj60 int
	var yyb60 bool
	var yyhl60 bool = l >= 0
	yyj60++
	if yyhl60 {
		yyb60 = yyj60 > l
	} else {
		yyb60 = r.CheckBreak()
	}
	if yyb60 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Kind = ""
	} else {
		x.Kind = string(r.DecodeString())
	}
	yyj60++
	if yyhl60 {
		yyb60 = yyj60 > l
	} else {
		yyb60 = r.CheckBreak()
	}
	if yyb60 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.APIVersion = ""
	} else {
		x.APIVersion = string(r.DecodeString())
	}
	yyj60++
	if yyhl60 {
		yyb60 = yyj60 > l
	} else {
		yyb60 = r.CheckBreak()
	}
	if yyb60 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.ObjectMeta = pkg2_v1.ObjectMeta{}
	} else {
		yyv63 := &x.ObjectMeta
		yyv63.CodecDecodeSelf(d)
	}
	yyj60++
	if yyhl60 {
		yyb60 = yyj60 > l
	} else {
		yyb60 = r.CheckBreak()
	}
	if yyb60 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Other = ""
	} else {
		x.Other = string(r.DecodeString())
	}
	yyj60++
	if yyhl60 {
		yyb60 = yyj60 > l
	} else {
		yyb60 = r.CheckBreak()
	}
	if yyb60 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Labels = nil
	} else {
		yyv65 := &x.Labels
		yym66 := z.DecBinary()
		_ = yym66
		if false {
		} else {
			z.F.DecMapStringStringX(yyv65, false, d)
		}
	}
	for {
		yyj60++
		if yyhl60 {
			yyb60 = yyj60 > l
		} else {
			yyb60 = r.CheckBreak()
		}
		if yyb60 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj60-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x *SimpleGetOptions) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym67 := z.EncBinary()
		_ = yym67
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep68 := !z.EncBinary()
			yy2arr68 := z.EncBasicHandle().StructToArray
			var yyq68 [5]bool
			_, _, _ = yysep68, yyq68, yy2arr68
			const yyr68 bool = false
			yyq68[0] = x.Kind != ""
			yyq68[1] = x.APIVersion != ""
			var yynn68 int
			if yyr68 || yy2arr68 {
				r.EncodeArrayStart(5)
			} else {
				yynn68 = 3
				for _, b := range yyq68 {
					if b {
						yynn68++
					}
				}
				r.EncodeMapStart(yynn68)
				yynn68 = 0
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq68[0] {
					yym70 := z.EncBinary()
					_ = yym70
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq68[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("kind"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym71 := z.EncBinary()
					_ = yym71
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				}
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq68[1] {
					yym73 := z.EncBinary()
					_ = yym73
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq68[1] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("apiVersion"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym74 := z.EncBinary()
					_ = yym74
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				}
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yym76 := z.EncBinary()
				_ = yym76
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.Param1))
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("param1"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yym77 := z.EncBinary()
				_ = yym77
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.Param1))
				}
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yym79 := z.EncBinary()
				_ = yym79
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.Param2))
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("param2"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yym80 := z.EncBinary()
				_ = yym80
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.Param2))
				}
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yym82 := z.EncBinary()
				_ = yym82
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.Path))
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("atAPath"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yym83 := z.EncBinary()
				_ = yym83
				if false {
				} else {
					r.EncodeString(codecSelferC_UTF81234, string(x.Path))
				}
			}
			if yyr68 || yy2arr68 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *SimpleGetOptions) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym84 := z.DecBinary()
	_ = yym84
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct85 := r.ContainerType()
		if yyct85 == codecSelferValueTypeMap1234 {
			yyl85 := r.ReadMapStart()
			if yyl85 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl85, d)
			}
		} else if yyct85 == codecSelferValueTypeArray1234 {
			yyl85 := r.ReadArrayStart()
			if yyl85 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl85, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *SimpleGetOptions) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys86Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys86Slc
	var yyhl86 bool = l >= 0
	for yyj86 := 0; ; yyj86++ {
		if yyhl86 {
			if yyj86 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys86Slc = r.DecodeBytes(yys86Slc, true, true)
		yys86 := string(yys86Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys86 {
		case "kind":
			if r.TryDecodeAsNil() {
				x.Kind = ""
			} else {
				x.Kind = string(r.DecodeString())
			}
		case "apiVersion":
			if r.TryDecodeAsNil() {
				x.APIVersion = ""
			} else {
				x.APIVersion = string(r.DecodeString())
			}
		case "param1":
			if r.TryDecodeAsNil() {
				x.Param1 = ""
			} else {
				x.Param1 = string(r.DecodeString())
			}
		case "param2":
			if r.TryDecodeAsNil() {
				x.Param2 = ""
			} else {
				x.Param2 = string(r.DecodeString())
			}
		case "atAPath":
			if r.TryDecodeAsNil() {
				x.Path = ""
			} else {
				x.Path = string(r.DecodeString())
			}
		default:
			z.DecStructFieldNotFound(-1, yys86)
		} // end switch yys86
	} // end for yyj86
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *SimpleGetOptions) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj92 int
	var yyb92 bool
	var yyhl92 bool = l >= 0
	yyj92++
	if yyhl92 {
		yyb92 = yyj92 > l
	} else {
		yyb92 = r.CheckBreak()
	}
	if yyb92 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Kind = ""
	} else {
		x.Kind = string(r.DecodeString())
	}
	yyj92++
	if yyhl92 {
		yyb92 = yyj92 > l
	} else {
		yyb92 = r.CheckBreak()
	}
	if yyb92 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.APIVersion = ""
	} else {
		x.APIVersion = string(r.DecodeString())
	}
	yyj92++
	if yyhl92 {
		yyb92 = yyj92 > l
	} else {
		yyb92 = r.CheckBreak()
	}
	if yyb92 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Param1 = ""
	} else {
		x.Param1 = string(r.DecodeString())
	}
	yyj92++
	if yyhl92 {
		yyb92 = yyj92 > l
	} else {
		yyb92 = r.CheckBreak()
	}
	if yyb92 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Param2 = ""
	} else {
		x.Param2 = string(r.DecodeString())
	}
	yyj92++
	if yyhl92 {
		yyb92 = yyj92 > l
	} else {
		yyb92 = r.CheckBreak()
	}
	if yyb92 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Path = ""
	} else {
		x.Path = string(r.DecodeString())
	}
	for {
		yyj92++
		if yyhl92 {
			yyb92 = yyj92 > l
		} else {
			yyb92 = r.CheckBreak()
		}
		if yyb92 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj92-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x *SimpleList) CodecEncodeSelf(e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	if x == nil {
		r.EncodeNil()
	} else {
		yym98 := z.EncBinary()
		_ = yym98
		if false {
		} else if z.HasExtensions() && z.EncExt(x) {
		} else {
			yysep99 := !z.EncBinary()
			yy2arr99 := z.EncBasicHandle().StructToArray
			var yyq99 [4]bool
			_, _, _ = yysep99, yyq99, yy2arr99
			const yyr99 bool = false
			yyq99[0] = x.Kind != ""
			yyq99[1] = x.APIVersion != ""
			yyq99[3] = len(x.Items) != 0
			var yynn99 int
			if yyr99 || yy2arr99 {
				r.EncodeArrayStart(4)
			} else {
				yynn99 = 1
				for _, b := range yyq99 {
					if b {
						yynn99++
					}
				}
				r.EncodeMapStart(yynn99)
				yynn99 = 0
			}
			if yyr99 || yy2arr99 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq99[0] {
					yym101 := z.EncBinary()
					_ = yym101
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq99[0] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("kind"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym102 := z.EncBinary()
					_ = yym102
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.Kind))
					}
				}
			}
			if yyr99 || yy2arr99 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq99[1] {
					yym104 := z.EncBinary()
					_ = yym104
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				} else {
					r.EncodeString(codecSelferC_UTF81234, "")
				}
			} else {
				if yyq99[1] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("apiVersion"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					yym105 := z.EncBinary()
					_ = yym105
					if false {
					} else {
						r.EncodeString(codecSelferC_UTF81234, string(x.APIVersion))
					}
				}
			}
			if yyr99 || yy2arr99 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				yy107 := &x.ListMeta
				yym108 := z.EncBinary()
				_ = yym108
				if false {
				} else if z.HasExtensions() && z.EncExt(yy107) {
				} else {
					z.EncFallback(yy107)
				}
			} else {
				z.EncSendContainerState(codecSelfer_containerMapKey1234)
				r.EncodeString(codecSelferC_UTF81234, string("metadata"))
				z.EncSendContainerState(codecSelfer_containerMapValue1234)
				yy109 := &x.ListMeta
				yym110 := z.EncBinary()
				_ = yym110
				if false {
				} else if z.HasExtensions() && z.EncExt(yy109) {
				} else {
					z.EncFallback(yy109)
				}
			}
			if yyr99 || yy2arr99 {
				z.EncSendContainerState(codecSelfer_containerArrayElem1234)
				if yyq99[3] {
					if x.Items == nil {
						r.EncodeNil()
					} else {
						yym112 := z.EncBinary()
						_ = yym112
						if false {
						} else {
							h.encSliceSimple(([]Simple)(x.Items), e)
						}
					}
				} else {
					r.EncodeNil()
				}
			} else {
				if yyq99[3] {
					z.EncSendContainerState(codecSelfer_containerMapKey1234)
					r.EncodeString(codecSelferC_UTF81234, string("items"))
					z.EncSendContainerState(codecSelfer_containerMapValue1234)
					if x.Items == nil {
						r.EncodeNil()
					} else {
						yym113 := z.EncBinary()
						_ = yym113
						if false {
						} else {
							h.encSliceSimple(([]Simple)(x.Items), e)
						}
					}
				}
			}
			if yyr99 || yy2arr99 {
				z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				z.EncSendContainerState(codecSelfer_containerMapEnd1234)
			}
		}
	}
}

func (x *SimpleList) CodecDecodeSelf(d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	yym114 := z.DecBinary()
	_ = yym114
	if false {
	} else if z.HasExtensions() && z.DecExt(x) {
	} else {
		yyct115 := r.ContainerType()
		if yyct115 == codecSelferValueTypeMap1234 {
			yyl115 := r.ReadMapStart()
			if yyl115 == 0 {
				z.DecSendContainerState(codecSelfer_containerMapEnd1234)
			} else {
				x.codecDecodeSelfFromMap(yyl115, d)
			}
		} else if yyct115 == codecSelferValueTypeArray1234 {
			yyl115 := r.ReadArrayStart()
			if yyl115 == 0 {
				z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
			} else {
				x.codecDecodeSelfFromArray(yyl115, d)
			}
		} else {
			panic(codecSelferOnlyMapOrArrayEncodeToStructErr1234)
		}
	}
}

func (x *SimpleList) codecDecodeSelfFromMap(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yys116Slc = z.DecScratchBuffer() // default slice to decode into
	_ = yys116Slc
	var yyhl116 bool = l >= 0
	for yyj116 := 0; ; yyj116++ {
		if yyhl116 {
			if yyj116 >= l {
				break
			}
		} else {
			if r.CheckBreak() {
				break
			}
		}
		z.DecSendContainerState(codecSelfer_containerMapKey1234)
		yys116Slc = r.DecodeBytes(yys116Slc, true, true)
		yys116 := string(yys116Slc)
		z.DecSendContainerState(codecSelfer_containerMapValue1234)
		switch yys116 {
		case "kind":
			if r.TryDecodeAsNil() {
				x.Kind = ""
			} else {
				x.Kind = string(r.DecodeString())
			}
		case "apiVersion":
			if r.TryDecodeAsNil() {
				x.APIVersion = ""
			} else {
				x.APIVersion = string(r.DecodeString())
			}
		case "metadata":
			if r.TryDecodeAsNil() {
				x.ListMeta = pkg1_v1.ListMeta{}
			} else {
				yyv119 := &x.ListMeta
				yym120 := z.DecBinary()
				_ = yym120
				if false {
				} else if z.HasExtensions() && z.DecExt(yyv119) {
				} else {
					z.DecFallback(yyv119, false)
				}
			}
		case "items":
			if r.TryDecodeAsNil() {
				x.Items = nil
			} else {
				yyv121 := &x.Items
				yym122 := z.DecBinary()
				_ = yym122
				if false {
				} else {
					h.decSliceSimple((*[]Simple)(yyv121), d)
				}
			}
		default:
			z.DecStructFieldNotFound(-1, yys116)
		} // end switch yys116
	} // end for yyj116
	z.DecSendContainerState(codecSelfer_containerMapEnd1234)
}

func (x *SimpleList) codecDecodeSelfFromArray(l int, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r
	var yyj123 int
	var yyb123 bool
	var yyhl123 bool = l >= 0
	yyj123++
	if yyhl123 {
		yyb123 = yyj123 > l
	} else {
		yyb123 = r.CheckBreak()
	}
	if yyb123 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Kind = ""
	} else {
		x.Kind = string(r.DecodeString())
	}
	yyj123++
	if yyhl123 {
		yyb123 = yyj123 > l
	} else {
		yyb123 = r.CheckBreak()
	}
	if yyb123 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.APIVersion = ""
	} else {
		x.APIVersion = string(r.DecodeString())
	}
	yyj123++
	if yyhl123 {
		yyb123 = yyj123 > l
	} else {
		yyb123 = r.CheckBreak()
	}
	if yyb123 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.ListMeta = pkg1_v1.ListMeta{}
	} else {
		yyv126 := &x.ListMeta
		yym127 := z.DecBinary()
		_ = yym127
		if false {
		} else if z.HasExtensions() && z.DecExt(yyv126) {
		} else {
			z.DecFallback(yyv126, false)
		}
	}
	yyj123++
	if yyhl123 {
		yyb123 = yyj123 > l
	} else {
		yyb123 = r.CheckBreak()
	}
	if yyb123 {
		z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
		return
	}
	z.DecSendContainerState(codecSelfer_containerArrayElem1234)
	if r.TryDecodeAsNil() {
		x.Items = nil
	} else {
		yyv128 := &x.Items
		yym129 := z.DecBinary()
		_ = yym129
		if false {
		} else {
			h.decSliceSimple((*[]Simple)(yyv128), d)
		}
	}
	for {
		yyj123++
		if yyhl123 {
			yyb123 = yyj123 > l
		} else {
			yyb123 = r.CheckBreak()
		}
		if yyb123 {
			break
		}
		z.DecSendContainerState(codecSelfer_containerArrayElem1234)
		z.DecStructFieldNotFound(yyj123-1, "")
	}
	z.DecSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x codecSelfer1234) encSliceSimple(v []Simple, e *codec1978.Encoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperEncoder(e)
	_, _, _ = h, z, r
	r.EncodeArrayStart(len(v))
	for _, yyv130 := range v {
		z.EncSendContainerState(codecSelfer_containerArrayElem1234)
		yy131 := &yyv130
		yy131.CodecEncodeSelf(e)
	}
	z.EncSendContainerState(codecSelfer_containerArrayEnd1234)
}

func (x codecSelfer1234) decSliceSimple(v *[]Simple, d *codec1978.Decoder) {
	var h codecSelfer1234
	z, r := codec1978.GenHelperDecoder(d)
	_, _, _ = h, z, r

	yyv132 := *v
	yyh132, yyl132 := z.DecSliceHelperStart()
	var yyc132 bool
	if yyl132 == 0 {
		if yyv132 == nil {
			yyv132 = []Simple{}
			yyc132 = true
		} else if len(yyv132) != 0 {
			yyv132 = yyv132[:0]
			yyc132 = true
		}
	} else if yyl132 > 0 {
		var yyrr132, yyrl132 int
		var yyrt132 bool
		if yyl132 > cap(yyv132) {

			yyrg132 := len(yyv132) > 0
			yyv2132 := yyv132
			yyrl132, yyrt132 = z.DecInferLen(yyl132, z.DecBasicHandle().MaxInitLen, 280)
			if yyrt132 {
				if yyrl132 <= cap(yyv132) {
					yyv132 = yyv132[:yyrl132]
				} else {
					yyv132 = make([]Simple, yyrl132)
				}
			} else {
				yyv132 = make([]Simple, yyrl132)
			}
			yyc132 = true
			yyrr132 = len(yyv132)
			if yyrg132 {
				copy(yyv132, yyv2132)
			}
		} else if yyl132 != len(yyv132) {
			yyv132 = yyv132[:yyl132]
			yyc132 = true
		}
		yyj132 := 0
		for ; yyj132 < yyrr132; yyj132++ {
			yyh132.ElemContainerState(yyj132)
			if r.TryDecodeAsNil() {
				yyv132[yyj132] = Simple{}
			} else {
				yyv133 := &yyv132[yyj132]
				yyv133.CodecDecodeSelf(d)
			}

		}
		if yyrt132 {
			for ; yyj132 < yyl132; yyj132++ {
				yyv132 = append(yyv132, Simple{})
				yyh132.ElemContainerState(yyj132)
				if r.TryDecodeAsNil() {
					yyv132[yyj132] = Simple{}
				} else {
					yyv134 := &yyv132[yyj132]
					yyv134.CodecDecodeSelf(d)
				}

			}
		}

	} else {
		yyj132 := 0
		for ; !r.CheckBreak(); yyj132++ {

			if yyj132 >= len(yyv132) {
				yyv132 = append(yyv132, Simple{}) // var yyz132 Simple
				yyc132 = true
			}
			yyh132.ElemContainerState(yyj132)
			if yyj132 < len(yyv132) {
				if r.TryDecodeAsNil() {
					yyv132[yyj132] = Simple{}
				} else {
					yyv135 := &yyv132[yyj132]
					yyv135.CodecDecodeSelf(d)
				}

			} else {
				z.DecSwallow()
			}

		}
		if yyj132 < len(yyv132) {
			yyv132 = yyv132[:yyj132]
			yyc132 = true
		} else if yyj132 == 0 && yyv132 == nil {
			yyv132 = []Simple{}
			yyc132 = true
		}
	}
	yyh132.End()
	if yyc132 {
		*v = yyv132
	}
}
