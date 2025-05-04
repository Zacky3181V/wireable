package config

import (
	"fmt"
	"log"
	"os"

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
	content := fmt.Sprintf(`[Interface]
Address = 10.0.0.1/24
PostUp = iptables -I FORWARD 1 -i wg0 -j ACCEPT; iptables -I FORWARD 1 -o wg0 -j ACCEPT; iptables -t nat -I POSTROUTING 1 -s 10.200.200.0/24 -o eth0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.200.200.0/24 -o eth0 -j MASQUERADE
ListenPort = 51820
PrivateKey = %s
`, privateKey)

	err := os.WriteFile("peers.conf", []byte(content), 0644)
	if err != nil {
		log.Fatalf("Failed to write peers.conf: %v", err)
	}
}
