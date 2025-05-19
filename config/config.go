package config

import (
	"log"
	"os"
	"text/template"
	"github.com/Zacky3181V/wireable/allocator"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	wgAllocator        *allocator.IPAllocator
	serverPrivateKey   wgtypes.Key
	serverPublicKey    wgtypes.Key
	privateKeyFile     = "server_private.key"
	wasKeyGeneratedNow bool
)

func init() {
	var err error
	wgAllocator, err = allocator.NewIPAllocator("10.0.0.0/24")
	if err != nil {
		log.Fatalf("Failed to initialize IPAllocator: %v", err)
	}
	log.Println("IPAllocator initialized successfully.")

	serverPrivateKey, serverPublicKey, wasKeyGeneratedNow, err = loadOrGenerateServerKeys()
	if err != nil {
		log.Fatalf("Failed to initialize WireGuard server keys: %v", err)
	}
	log.Println("WireGuard server keys initialized.")

	if wasKeyGeneratedNow {
		log.Println("New WireGuard private key generated. Creating fresh server config")
		writeInitialPeersFile(serverPrivateKey.String())
	} else {
		log.Println("Using existing WireGuard private key. Skipping config rewrite")
	}
}

func GetAllocator() *allocator.IPAllocator {
	return wgAllocator
}

func GetServerPublicKey() string {
	return serverPublicKey.String()
}

func GetServerPrivateKey() string {
	return serverPrivateKey.String()
}

func loadOrGenerateServerKeys() (wgtypes.Key, wgtypes.Key, bool, error) {
	// Try loading private key from file
	if data, err := os.ReadFile(privateKeyFile); err == nil {
		privKey, err := wgtypes.ParseKey(string(data))
		if err != nil {
			return wgtypes.Key{}, wgtypes.Key{}, false, err
		}
		return privKey, privKey.PublicKey(), false, nil
	}

	// Else generate a new one
	privKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, false, err
	}

	// Save private key to file
	err = os.WriteFile(privateKeyFile, []byte(privKey.String()), 0600)
	if err != nil {
		return wgtypes.Key{}, wgtypes.Key{}, false, err
	}

	return privKey, privKey.PublicKey(), true, nil
}

func writeInitialPeersFile(privateKey string) {
	tmplContent, err := os.ReadFile("./templates/server_template.conf")
	if err!=nil{
		log.Fatalf("Failed to read server template file %v", err)
	}

	tmpl, err := template.New("server").Parse(string(tmplContent))
	if err != nil {
		log.Fatalf("Failed to parse template: %v", err)
	}

	file, err := os.Create("peers.conf")
	if err != nil {
		log.Fatalf("Failed to create peers.conf: %v", err)
	}
	defer file.Close()

	err = tmpl.Execute(file, struct {
		PrivateKey string
	}{
		PrivateKey: privateKey,
	})
	if err != nil {
		log.Fatalf("Failed to execute template: %v", err)
	}

}
