package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// setter is a value that reads itself from the configuration: what is no mapping, boolean,
// string nor whole number, as a duration. path is where it is, for its errors.
type setter interface {
	set(path string, raw json.RawMessage) error
}

// decode reads raw, a JSON value, into v, strictly: a key the type doesn't have is an error that
// names those it has, and so is a value of another type than its key takes. What the document
// leaves out, or leaves null, stays as v has it: the defaults. Every error is told, not the first
// alone, each with the path of its key, as protocols.mdns.ask.
func decode(path string, raw json.RawMessage, v reflect.Value) error {
	raw = bytes.TrimSpace(raw)
	if string(raw) == "null" || len(raw) == 0 {
		return nil
	}
	if s, ok := v.Addr().Interface().(setter); ok {
		return s.set(path, raw)
	}
	switch v.Kind() {
	case reflect.Struct:
		object, err := mapping(path, raw, v.Type())
		if err != nil {
			return err
		}
		fields := fieldsOf(v.Type())
		var errs []error
		for _, key := range slices.Sorted(mapKeys(object)) {
			index, ok := fields.index[key]
			if !ok {
				errs = append(errs, unknownKey(path, key, fields.names))
				continue
			}
			errs = append(errs, decode(join(path, key), object[key], v.FieldByIndex(index)))
		}
		return errors.Join(errs...)
	case reflect.Map:
		object, err := mapping(path, raw, v.Type())
		if err != nil {
			return err
		}
		if v.IsNil() {
			v.Set(reflect.MakeMap(v.Type()))
		}
		var errs []error
		for _, key := range slices.Sorted(mapKeys(object)) {
			element := reflect.New(v.Type().Elem()).Elem()
			if existing := v.MapIndex(reflect.ValueOf(key)); existing.IsValid() {
				element.Set(existing)
			}
			if string(bytes.TrimSpace(object[key])) == "null" {
				errs = append(errs, fmt.Errorf("%s: it is empty", join(path, key)))
				continue
			}
			if err := decode(join(path, key), object[key], element); err != nil {
				errs = append(errs, err)
				continue
			}
			v.SetMapIndex(reflect.ValueOf(key), element)
		}
		return errors.Join(errs...)
	case reflect.Bool:
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			return fmt.Errorf("%s: %s is not true or false", path, raw)
		}
		v.SetBool(b)
	case reflect.String:
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return fmt.Errorf("%s: %s is not a string", path, raw)
		}
		v.SetString(s)
	case reflect.Int:
		var n int
		if json.Unmarshal(raw, &n) != nil {
			return fmt.Errorf("%s: %s is not a whole number", path, raw)
		}
		v.SetInt(int64(n))
	default:
		return fmt.Errorf("%s: a %s can't be read", path, v.Type())
	}
	return nil
}

// mapping reads raw as the keys of a mapping, for a value of typ. Anything else is told with how
// the mapping is written, where a switch was given in place of its settings: mdns: true.
func mapping(path string, raw json.RawMessage, typ reflect.Type) (map[string]json.RawMessage, error) {
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err == nil {
		return object, nil
	}
	key := path[strings.LastIndex(path, ".")+1:]
	if path == "" {
		return nil, fmt.Errorf("the configuration is %s, not a mapping of its keys", raw)
	}
	var on bool
	if typ.Kind() == reflect.Struct && json.Unmarshal(raw, &on) == nil {
		if path == "hostnames" {
			return nil, fmt.Errorf("hostnames: %s: %s", raw, namesAlwaysKept)
		}
		if _, ok := fieldsOf(typ).index["enabled"]; ok {
			return nil, fmt.Errorf("%s: %s is not its settings: it is written as %s, with enabled: %t under it", path, raw, key, on)
		}
	}
	return nil, fmt.Errorf("%s: %s is not a mapping of its keys", path, raw)
}

// namesAlwaysKept is what a switch of the names, which there was, is now.
const namesAlwaysKept = "the names are no longer switched: they are kept, of the protocols that learn them; to learn none, disable those under protocols, as mdns, netbios, llmnr and dhcp, and the names of ssdp and wsd"

// unknownKey is the error of a key nothing has, at path: a protocol there is none of, an option
// its protocol doesn't have, or a key of any other mapping, each with those there are.
func unknownKey(path, key string, known []string) error {
	list := strings.Join(known, ", ")
	parent, protocol, of := strings.Cut(path, ".")
	switch {
	case path == "hostnames" && key == "enabled":
		return fmt.Errorf("hostnames.enabled: %s", namesAlwaysKept)
	case path == "":
		return fmt.Errorf("%s: no such key: the configuration has %s", key, list)
	case path == "protocols":
		return fmt.Errorf("%s: no such protocol: they are %s", join(path, key), list)
	case parent == "protocols" && of:
		return fmt.Errorf("%s: no such option of %s: it has %s", join(path, key), protocol, list)
	}
	return fmt.Errorf("%s: no such key: %s has %s", join(path, key), path, list)
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func mapKeys[V any](m map[string]V) func(yield func(string) bool) {
	return func(yield func(string) bool) {
		for key := range m {
			if !yield(key) {
				return
			}
		}
	}
}

// fields are the keys a struct is written with: those its fields' json tags name, in their
// order, with those of the structs embedded in it among them.
type fields struct {
	names []string
	index map[string][]int
}

func fieldsOf(typ reflect.Type) fields {
	result := fields{index: make(map[string][]int)}
	for _, field := range reflect.VisibleFields(typ) {
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if !field.IsExported() || field.Anonymous || name == "" || name == "-" {
			continue
		}
		result.names = append(result.names, name)
		result.index[name] = field.Index
	}
	return result
}
