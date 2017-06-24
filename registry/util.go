package saultregistry

func NewTestRegistryFromBytes(b []byte) (registry *Registry, err error) {
	source, _ := LoadRegistrySourceFromConfig(
		map[string]interface{}{"type": "bytes", "b": ""},
		map[string]interface{}{"BaseDirectory": "./"},
	)

	registry = NewRegistry()
	registry.AddSource(source)

	err = registry.Load()

	return
}
