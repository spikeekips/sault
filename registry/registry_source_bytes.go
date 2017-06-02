package saultregistry

type bytesConfigRegistry struct {
	Type string // must be 'bytes'
	B    []byte
}

func (t bytesConfigRegistry) GetType() string {
	return "bytes"
}

func (t bytesConfigRegistry) Bytes() (b []byte, err error) {
	b = t.B
	return
}

func (t bytesConfigRegistry) Save(p []byte) (err error) {
	t.B = p
	return
}

func (t bytesConfigRegistry) Validate() (err error) {
	return nil
}
