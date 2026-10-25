package web

// burpsy-react-ui-j0s2: encoding/json v1 encodes a nil slice as null, and the UI types these
// collections as arrays - "tree":null crashed it until 2f8c1f7d fixed that one route by hand.
// writeJSON routes every response through normalizeNilSlices, which rebuilds the value with each
// nil slice replaced by an empty slice of the same type. Only nil slices change: nil pointers,
// nil maps, nil interfaces, byte slices (they encode as base64 strings, so null and "" are both
// typed strings, not arrays) and anything a type marshals itself keep their old encoding,
// because those nulls carry meaning where a nil slice's never did.

import (
	"encoding/json"
	"reflect"
)

var marshalerType = reflect.TypeOf((*json.Marshaler)(nil)).Elem()

// cloneVisit identifies one pointer, map or slice header so repeated references share one clone
// (alias identity is preserved) and a cyclic graph terminates instead of recursing forever. The
// encoder then reports the cycle exactly as it would have on the original value.
type cloneVisit struct {
	typ reflect.Type
	ptr uintptr
	len int
}

type nilSliceNormaliser struct {
	clones map[cloneVisit]reflect.Value
}

// normalizeNilSlices returns a copy of v with every nil slice replaced by an empty slice of the
// same type, walking pointers, interfaces, structs (exported fields), slices, arrays and map
// values. The input is never mutated: DTOs can share backing arrays with store state.
//
// Supported-DTO contract (pinned by json_nil_slice_test.go): the value is a response DTO built
// for encoding/json - exported fields, no functions/channels/unsafe pointers. Untouched by
// design: nil pointers/maps/interfaces; byte slices (base64 strings on the wire); anything a
// type marshals itself (json.Marshaler); unexported fields; map keys. Aliased pointers, maps
// and slice headers share one clone, so identity is preserved and a cyclic graph terminates
// here and is reported by the encoder exactly as it would have been on the original value.
func normalizeNilSlices(v reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}
	n := &nilSliceNormaliser{clones: map[cloneVisit]reflect.Value{}}
	return n.walk(v)
}

func (n *nilSliceNormaliser) walk(v reflect.Value) reflect.Value {
	// A type that marshals itself owns its encoding, including what it does with a nil slice;
	// walking into it would let the normaliser change what its MarshalJSON observes.
	if v.Type().Implements(marshalerType) || reflect.PointerTo(v.Type()).Implements(marshalerType) {
		return v
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		key := cloneVisit{v.Type(), v.Pointer(), 0}
		if seen, ok := n.clones[key]; ok {
			return seen
		}
		out := reflect.New(v.Elem().Type())
		n.clones[key] = out
		out.Elem().Set(n.walk(v.Elem()))
		return out
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		return n.walk(v.Elem())
	case reflect.Slice:
		// Byte slices encode as base64 strings, not arrays: an empty one is "" where nil was
		// null. json.RawMessage is covered by the marshaler rule above; plain []byte here.
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return v
		}
		if v.IsNil() {
			return reflect.MakeSlice(v.Type(), 0, 0)
		}
		key := cloneVisit{v.Type(), v.Pointer(), v.Len()}
		if seen, ok := n.clones[key]; ok {
			return seen
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		n.clones[key] = out
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(n.walk(v.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(n.walk(v.Index(i)))
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				out.Field(i).Set(n.walk(v.Field(i)))
			}
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		key := cloneVisit{v.Type(), v.Pointer(), 0}
		if seen, ok := n.clones[key]; ok {
			return seen
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		n.clones[key] = out
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), n.walk(iter.Value()))
		}
		return out
	default:
		return v
	}
}
