package utils

import (
	"errors"
	"fmt"
	serialize "github.com/TRON-US/go-btfs-config/serialize"
	"github.com/libp2p/go-libp2p-core/peer"
	"github.com/mitchellh/go-homedir"
	_ "github.com/mitchellh/go-homedir"
	"github.com/tron-us/go-btfs-common/crypto"
	"github.com/tron-us/go-common/v2/env"
	"os"
	"path/filepath"
)

type ApiConfigStruct struct {
	PrivateKey       string
	PeerId           string
	PublicKey        string
	SessionSignature string
}

const (
	// DefaultPathRoot is the path to the default config dir location.
	DefaultApiPathRoot = "~/"
	// DefaultConfigFile is the filename of the configuration file
	DefaultApiConfigFile = ".config"
	// EnvDir is the environment variable used to change the path root.
	EnvDir = "BTFS_PATH"
)

var ApiConfig ApiConfigStruct

func init() {
	//get variables via environment variable
	if _, s := env.GetEnv("PRIVATE_KEY"); s != "" {
		ApiConfig.PrivateKey = s
	}

	if _, s := env.GetEnv("PEER_ID"); s != "" {
		ApiConfig.PeerId = s
	}
	if _, s := env.GetEnv("PUBLIC_KEY"); s != "" {
		ApiConfig.PublicKey = s
	}
}

// Precondition: Call This function when any of the member variables of the
// ApiConfig object has zero value.
func LoadApiConfig() error {
	// if init() already loaded the variables, just return
	if GetPeerId() != "" && GetPrivateKey() != "" && GetPublicKey() != "" {
		return nil
	}

	spath, err := apiConfigFilename()
	if err != nil {
		return err
	}

	config, err := serialize.Load(spath)
	if err != nil {
		return err
	}

	if ApiConfig.PrivateKey == "" {
		privateKey := config.Identity.PrivKey
		if privateKey == "" {
			return errors.New("Identity.PrivKey is not set in .config file")
		}
		ApiConfig.PrivateKey = privateKey
	}

	if ApiConfig.PeerId == "" {
		peerId := config.Identity.PeerID
		if peerId == "" {
			return errors.New("Identity.PeerID is not set in .config file")
		}
		ApiConfig.PeerId = peerId
	}

	if ApiConfig.PublicKey == "" {
		peerId, err := peer.IDB58Decode(ApiConfig.PeerId)
		if err != nil {
			return err
		}
		publicKey, err := peerId.ExtractPublicKey()
		if err != nil {
			return err
		}
		publicKeyStr, err := crypto.FromPubKey(publicKey)
		if err != nil {
			return err
		}
		ApiConfig.PublicKey = publicKeyStr
	}

	fmt.Println("Loaded peer id: " + ApiConfig.PeerId)
	fmt.Println("Loaded public key: " + ApiConfig.PublicKey)

	return nil
}

func apiPathRoot() (string, error) {
	dir := os.Getenv(EnvDir)
	var err error
	if len(dir) == 0 {
		dir, err = homedir.Expand(DefaultApiPathRoot)
	}
	return dir, err
}

func apiPath(extension string) (string, error) {
	dir, err := apiPathRoot()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, extension), nil
}

func apiConfigFilename() (string, error) {
	return apiPath(DefaultApiConfigFile)
}

func GetPrivateKey() string {
	return ApiConfig.PrivateKey
}

func GetPublicKey() string {
	return ApiConfig.PublicKey
}

func GetPeerId() string {
	return ApiConfig.PeerId
}

func GetSessionSignature() string {
	return ApiConfig.SessionSignature
}

func SetSessionSignature(sessionSig string) {
	ApiConfig.SessionSignature = sessionSig
}
