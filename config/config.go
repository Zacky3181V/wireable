package config

import (
	"log"
	"os"

	"github.com/Zacky3181V/wireable/allocator"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	wgAllocator      *allocator.IPAllocator
	serverPrivateKey wgtypes.Key
	serverPublicKey  wgtypes.Key
	privateKeyFile   = "server_private.key"
)

func init() {
	var err error
	wgAllocator, err = allocator.NewIPAllocator("10.0.0.0/24")
	if err != nil {
		log.Fatalf("Failed to initialize IPAllocator: %v", err)
	}
	log.Println("IPAllocator initialized successfully.")


	serverPrivateKey, serverPublicKey, err = loadOrGenerateServerKeys()
	if err != nil {
		log.Fatalf("Failed to initialize WireGuard server keys: %v", err)
	}
	log.Println("WireGuard server keys initialized.")
}

func GetAllocator() *allocator.IPAllocator {
	return wgAllocator
}

func GetServerPublicKey() (string){
	return serverPublicKey.String()
}

func GetServerPrivateKey() (string) {
	return serverPrivateKey.String()
}

func loadOrGenerateServerKeys() (wgtypes.Key, wgtypes.Key, error) {
	// Try loading private key from file
	if data, err := os.ReadFile(privateKeyFile); err == nil {
		privKey, err := wgtypes.ParseKey(string(data))
		if err != nil {
			return wgtypes.Key{}, wgtypes.Key{}, err
		}
		return privKey, privKey.PublicKey(), nil
	}

	// Else generate a new one
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}

	// Save private key to file
	err = os.WriteFile(privateKeyFile, []byte(privKey.String()), 0600)
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, err
	}

	return privKey, privKey.PublicKey(), nil
}

