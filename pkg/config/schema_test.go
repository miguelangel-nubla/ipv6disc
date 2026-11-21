package config

import (
	"encoding/json"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/miguelangel-nubla/ipv6disc/pkg/plugins"
)

func schemaDocument(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatalf("the schema: %v", err)
	}
	return document
}

// The schema and the types a file is read into agree: every property is a field, every field a
// property, of the same type, and no object takes a key it doesn't name. Each property says
// what it is, and its default, which is the one of Default.
func TestSchemaMatchesConfig(t *testing.T) {
	document := schemaDocument(t, Schema())
	defaults, err := json.Marshal(Default())
	if err != nil {
		t.Fatal(err)
	}
	var defaultValues map[string]any
	if err := json.Unmarshal(defaults, &defaultValues); err != nil {
		t.Fatal(err)
	}
	checkSchema(t, document, "", document, reflect.TypeFor[File](), defaultValues)
}

// checkSchema compares the schema of the value at path with its type, and its defaults with
// those the value has by default.
func checkSchema(t *testing.T, document map[string]any, path string, schema map[string]any, typ reflect.Type, value any) {
	t.Helper()
	if path != "" && !strings.HasSuffix(path, ".*") && schema["description"] == nil {
		t.Errorf("%s: no description", path)
	}
	ref, _ := schema["$ref"].(string)
	switch {
	case ref == "#/$defs/duration":
		if typ != reflect.TypeFor[Duration]() {
			t.Errorf("%s: the schema has a duration, the type is %s", path, typ)
		}
		if written, ok := schema["default"].(string); ok {
			var d Duration
			if err := d.set(path, json.RawMessage(`"`+written+`"`)); err != nil || d.String() != value {
				t.Errorf("%s: the schema's default is %s, the configuration's %v", path, written, value)
			}
		} else if value != "0s" {
			t.Errorf("%s: no default in the schema, and the configuration's is %v", path, value)
		}
		return
	case ref == "#/$defs/stringList":
		if typ != reflect.TypeFor[StringList]() && typ != reflect.TypeFor[Servers]() {
			t.Errorf("%s: the schema has a list of strings, the type is %s", path, typ)
		}
		return
	case ref == "#/$defs/plugin":
		if typ != reflect.TypeFor[Plugin]() {
			t.Errorf("%s: the schema has a plugin, the type is %s", path, typ)
		}
		return
	case ref != "":
		t.Errorf("%s: %s is not looked at", path, ref)
		return
	}

	switch schema["type"] {
	case "object":
		if element, ok := schema["additionalProperties"].(map[string]any); ok {
			if typ.Kind() != reflect.Map {
				t.Errorf("%s: the schema is a map, the type %s isn't", path, typ)
				return
			}
			checkSchema(t, document, path+".*", element, typ.Elem(), nil)
			return
		}
		if schema["additionalProperties"] != false {
			t.Errorf("%s: it takes keys it doesn't name", path)
		}
		if typ.Kind() != reflect.Struct {
			t.Errorf("%s: the schema has properties, the type %s has no fields", path, typ)
			return
		}
		properties, _ := schema["properties"].(map[string]any)
		known := fieldsOf(typ)
		values, _ := value.(map[string]any)
		for name, property := range properties {
			index, ok := known.index[name]
			if !ok {
				t.Errorf("%s: a property with no field in %s", join(path, name), typ)
				continue
			}
			checkSchema(t, document, join(path, name), property.(map[string]any), typ.FieldByIndex(index).Type, values[name])
		}
		for _, name := range known.names {
			if _, ok := properties[name]; !ok {
				t.Errorf("%s: a field of %s the schema doesn't have", join(path, name), typ)
			}
		}
	case "boolean", "integer", "string":
		want := map[string]reflect.Kind{"boolean": reflect.Bool, "integer": reflect.Int, "string": reflect.String}[schema["type"].(string)]
		if typ.Kind() != want {
			t.Errorf("%s: the schema type %v doesn't fit %s", path, schema["type"], typ)
		}
		written, has := schema["default"]
		switch {
		// On where the system can run it: the schema says so in words.
		case path == "protocols.arp-listen.enabled", path == "protocols.dhcp.enabled", path == "protocols.lldp.enabled":
			if has || !strings.Contains(schema["description"].(string), "Default: true on Linux") {
				t.Errorf("%s: the default depends on the system, which the description says: %v", path, schema["description"])
			}
		case !has:
			t.Errorf("%s: no default", path)
		case fmt.Sprint(written) != fmt.Sprint(value):
			t.Errorf("%s: the schema's default is %v, the configuration's %v", path, written, value)
		}
	default:
		t.Errorf("%s: a schema of type %v is not looked at", path, schema["type"])
	}
}

// The bounds, and the choices, the schema gives are the code's.
func TestSchemaBounds(t *testing.T) {
	document := schemaDocument(t, Schema())
	at := func(path ...string) map[string]any {
		node := document
		for _, key := range path {
			next, ok := node[key].(map[string]any)
			if !ok {
				t.Fatalf("the schema has no %s", strings.Join(path, "."))
			}
			node = next
		}
		return node
	}
	sweep := at("properties", "protocols", "properties", "arp-sweep", "properties", "max_prefix")
	for bound, in := range map[float64]bool{15: false, 16: true, 30: true, 31: false} {
		within := bound >= sweep["minimum"].(float64) && bound <= sweep["maximum"].(float64)
		_, err := Parse(fmt.Appendf(nil, "protocols:\n  arp-sweep:\n    max_prefix: %v", bound))
		if within != in || (err == nil) != in {
			t.Errorf("a max_prefix of %v: in the schema's range %v, read %v", bound, within, err)
		}
	}
	var levels []string
	for _, level := range at("properties", "log_level")["enum"].([]any) {
		levels = append(levels, level.(string))
	}
	if !slices.Equal(levels, LogLevels()) {
		t.Errorf("the levels of the schema: %v, of the code: %v", levels, LogLevels())
	}
	// The reverse DNS, on by default, asks nobody without servers: none are needed.
	if dns := at("properties", "protocols", "properties", "dns"); dns["then"] != nil || dns["required"] != nil {
		t.Errorf("the servers of dns are needed: %v", dns)
	}
}

// The plugins of the schema are those registered, each with its fields: their names, their
// types, their descriptions, and those needed.
func TestSchemaPlugins(t *testing.T) {
	document := schemaDocument(t, Schema())
	defs := document["$defs"].(map[string]any)
	plugin := defs["plugin"].(map[string]any)
	var types []string
	for _, name := range plugin["properties"].(map[string]any)["type"].(map[string]any)["enum"].([]any) {
		types = append(types, name.(string))
	}
	if !slices.Equal(types, plugins.Types()) {
		t.Fatalf("the plugin types of the schema: %v, registered: %v", types, plugins.Types())
	}
	// The schema of each type: the one its condition leads to.
	of := make(map[string]map[string]any)
	for _, branch := range plugin["allOf"].([]any) {
		branch := branch.(map[string]any)
		condition := branch["if"].(map[string]any)["properties"].(map[string]any)["type"].(map[string]any)
		names, _ := condition["enum"].([]any)
		if name, ok := condition["const"]; ok {
			names = []any{name}
		}
		ref := strings.TrimPrefix(branch["then"].(map[string]any)["$ref"].(string), "#/$defs/")
		for _, name := range names {
			of[name.(string)] = defs[ref].(map[string]any)
		}
	}
	for _, name := range plugins.Types() {
		schema, ok := of[name]
		if !ok {
			t.Errorf("the schema has no fields of a %s plugin", name)
			continue
		}
		if schema["additionalProperties"] != false {
			t.Errorf("a %s plugin takes fields it doesn't name", name)
		}
		properties := schema["properties"].(map[string]any)
		fields, _ := plugins.Fields(name)
		var required []any
		for _, field := range fields {
			property, ok := properties[field.Name].(map[string]any)
			if !ok {
				t.Errorf("a %s plugin: the schema has no %s", name, field.Name)
				continue
			}
			if property["description"] != field.Description {
				t.Errorf("a %s plugin, %s: the schema says %q, the plugin %q", name, field.Name, property["description"], field.Description)
			}
			got := fmt.Sprint(property["type"])
			if property["$ref"] == "#/$defs/duration" {
				got = plugins.FieldDuration
			}
			want := field.Type
			if want == "" {
				want = "string"
			}
			if got != want {
				t.Errorf("a %s plugin, %s: the schema has a %s, the plugin a %s", name, field.Name, got, want)
			}
			if field.Required {
				required = append(required, field.Name)
			}
		}
		if len(properties) != len(fields)+1 || properties["type"] == nil {
			t.Errorf("a %s plugin: %d properties in the schema, want its type and its %d fields", name, len(properties), len(fields))
		}
		if !reflect.DeepEqual(schema["required"], required) {
			t.Errorf("a %s plugin needs %v in the schema, %v by its fields", name, schema["required"], required)
		}
	}
}

// The schema of the discovery is the file's without what is the command's alone.
func TestDiscoverySchema(t *testing.T) {
	file, discovery := schemaDocument(t, Schema()), schemaDocument(t, DiscoverySchema())
	properties := discovery["properties"].(map[string]any)
	if _, ok := properties["log_level"]; ok {
		t.Error("the discovery has the level of the log")
	}
	delete(file["properties"].(map[string]any), "log_level")
	if !reflect.DeepEqual(file["properties"], properties) || !reflect.DeepEqual(file["$defs"], discovery["$defs"]) {
		t.Error("the discovery's schema is not the file's without log_level")
	}
	// And it is the type's.
	defaults, _ := json.Marshal(DefaultDiscovery())
	var defaultValues map[string]any
	if err := json.Unmarshal(defaults, &defaultValues); err != nil {
		t.Fatal(err)
	}
	checkSchema(t, discovery, "", discovery, reflect.TypeFor[Discovery](), defaultValues)
	// Schema returns a copy: what is done to it changes nothing.
	copy(Schema(), "garbage")
	schemaDocument(t, Schema())
}
