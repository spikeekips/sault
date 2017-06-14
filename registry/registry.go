package saultregistry

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/naoina/toml"
	"github.com/spikeekips/sault/common"
)

// RegistrySource is the source of registry
type RegistrySource interface {
	GetType() string
	Bytes() ([]byte, error)
	Save(p []byte) (err error)
	Validate() (err error)
}

// LoadRegistrySourceFromConfig load registry from config
func LoadRegistrySourceFromConfig(data map[string]interface{}, config map[string]interface{}) (rs RegistrySource, err error) {
	var sourceType string
	var ok bool
	if sourceType, ok = data["type"].(string); !ok {
		err = fmt.Errorf("'type' is missing in data, map[string]interface{}")
		return
	}

	var b bytes.Buffer
	toml.NewEncoder(&b).Encode(data)

	switch sourceType {
	case "toml":
		if rs, err = newTomlConfigRegistry(b.Bytes(), config); err != nil {
			return
		}
	case "bytes":
		var b bytes.Buffer
		rs = &bytesConfigRegistry{}
		if err = saultcommon.DefaultTOML.NewDecoder(&b).Decode(rs); err != nil {
			return
		}
	}

	return
}

// Registry is the registry
type Registry struct {
	Data *RegistryData

	// the source, which is loaded without err will be used from first
	Source []RegistrySource
}

// NewRegistry makes registry
func NewRegistry() (registry *Registry) {
	registry = &Registry{}
	registry.Source = []RegistrySource{}

	return registry
}

// RegistryDataCmpByTimeUpdated helps to compare the registry sources
type RegistryDataCmpByTimeUpdated []*RegistryData

func (s RegistryDataCmpByTimeUpdated) Len() int {
	return len(s)
}

func (s RegistryDataCmpByTimeUpdated) Less(i, j int) bool {
	return s[i].TimeUpdated.Before(s[j].TimeUpdated)
}

func (s RegistryDataCmpByTimeUpdated) Swap(i, j int) {
	s[i], s[j] = s[j], s[i]
	return
}

// AddSource add registry source to registry
func (registry *Registry) AddSource(source ...RegistrySource) (err error) {
	for _, s := range source {
		if err = s.Validate(); err != nil {
			return
		}

		registry.Source = append(registry.Source, s)
	}
	return
}

// Load loads registry from sources
func (registry *Registry) Load() (err error) {
	if len(registry.Source) < 1 {
		err = fmt.Errorf("sources are empty")
		return
	}

	var allData RegistryDataCmpByTimeUpdated
	for _, source := range registry.Source {
		data, err := NewRegistryDataFromSource(source)
		if err != nil {
			jsoned, _ := json.Marshal(source)
			log.Errorf("failed to load 'RegistryData' from source, '%s'", jsoned)
			continue
		}
		allData = append(allData, data)
	}

	if len(allData) < 1 {
		err = fmt.Errorf("failed to load RegistryData from sources")
		return
	}

	sort.Sort(sort.Reverse(allData))

	registry.Data = allData[0]

	return
}

// Bytes returns []byte of registry
func (registry *Registry) Bytes() []byte {
	var b bytes.Buffer
	toml.NewEncoder(&b).Encode(registry.Data)

	return b.Bytes()
}

// Save will save registry to sources
func (registry *Registry) Save() (err error) {
	if len(registry.Source) < 1 {
		err = fmt.Errorf("sources are empty")
		return
	}

	data := registry.Bytes()

	var saved bool
	for i := len(registry.Source) - 1; i >= 0; i-- {
		source := registry.Source[i]
		err = source.Save(data)
		if err != nil {
			jsoned, _ := json.Marshal(source)
			log.Errorf("failed to save registry to source, '%s'", jsoned)
			continue
		}

		saved = true
	}
	if !saved {
		err = fmt.Errorf("failed to save registry to sources")
		return
	}

	return nil
}
