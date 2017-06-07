package saultcommon

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/spikeekips/sault/sssh"
)

type FlagPrivateKey struct {
	Path   string
	Signer sssh.Signer
}

func (f *FlagPrivateKey) String() string {
	return f.Path
}

func (f *FlagPrivateKey) Set(file string) (err error) {
	file = filepath.Clean(file)

	{
		// trying to find signer from ssh agent with private key file name
		var signer sssh.Signer
		signer, err = FindSignerInSSHAgentFromFile(file)
		if err == nil {
			*f = FlagPrivateKey{Path: file, Signer: signer}
			return
		}
	}

	{
		// trying to find signer from ssh agent with loading private key
		var b []byte
		b, err = ioutil.ReadFile(file)
		if err != nil {
			return
		}

		var signer sssh.Signer
		var tmpSigner sssh.Signer
		tmpSigner, err = GetSignerFromPrivateKey(b)
		if err != nil {
			log.Debugf("failed to load signer from '%s' without passpharase", file)
		} else {
			signer, err = FindSignerInSSHAgentFromPublicKey(tmpSigner.PublicKey())
			if err != nil {
				log.Error(err)
			} else {
				*f = FlagPrivateKey{Path: file, Signer: signer}
				return
			}
		}
	}

	{
		// passpharase trial
		var signer sssh.Signer
		signer, err = LoadPrivateKeySignerWithPasspharaseTrial(file)
		if err != nil {
			log.Error(err)
		} else {
			*f = FlagPrivateKey{Path: file, Signer: signer}
			return
		}
	}

	err = fmt.Errorf("failed to load private identity from '%s'", file)
	log.Error(err)
	return
}

type FlagSaultServer struct {
	SaultServerName string
	Address         string
}

func (f *FlagSaultServer) String() string {
	return fmt.Sprintf("%s@%s", f.SaultServerName, f.Address)
}

func (f *FlagSaultServer) Set(v string) error {
	account, address, err := ParseHostAccount(v)
	if err != nil {
		return err
	}
	_, _, err = SplitHostPort(address, uint64(22))
	if err != nil {
		return err
	}

	surplus, saultServerName, err := ParseSaultAccountName(account)
	if err != nil {
		return err
	}
	if len(surplus) > 0 {
		return fmt.Errorf("in 'inSaultServer', '+' connected account name is prohibited")
	}
	if len(saultServerName) < 1 {
		return fmt.Errorf("sault server name is missing")
	}

	*f = FlagSaultServer{SaultServerName: account, Address: address}

	return nil
}
