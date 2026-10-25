package web

// burpsy-react-ui-j0s2: encoding/json v1 encodes a nil slice as null, and the UI types these
// collections as arrays - "tree":null crashed it until 2f8c1f7d fixed that one route by hand.
// writeJSON routes every response through normalizeNilSlices, which rebuilds the value with each
// nil slice replaced by an empty slice of the same type. Only nil slices change: nil pointers,
// nil maps and nil interfaces keep encoding as null, because those nulls carry meaning (an absent
// optional field), while no endpoint deliberately distinguishes "no collection" from "empty
// collection".

import "reflect"

// normalizeNilSlices returns a copy of v with every nil slice replaced by an empty slice of the
// same type, walking pointers, interfaces, structs (exported fields), slices, arrays and map
// values. The input is never mutated: DTOs can share backing arrays with store state.
func normalizeNilSlices(v reflect.Value) reflect.Value {
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			return v
		}
		out := reflect.New(v.Elem().Type())
		out.Elem().Set(normalizeNilSlices(v.Elem()))
		if v.Kind() == reflect.Interface {
			return out.Elem().Convert(v.Type())
		}
		return out
	case reflect.Slice:
		if v.IsNil() {
			return reflect.MakeSlice(v.Type(), 0, 0)
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(normalizeNilSlices(v.Index(i)))
		}
		return out
	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(normalizeNilSlices(v.Index(i)))
		}
		return out
	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)
		for i := 0; i < v.NumField(); i++ {
			if v.Type().Field(i).IsExported() {
				out.Field(i).Set(normalizeNilSlices(v.Field(i)))
			}
		}
		return out
	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(iter.Key(), normalizeNilSlices(iter.Value()))
		}
		return out
	default:
		return v
	}
}
