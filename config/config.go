package config

import (
	"container/heap"
	"context"
	"log"
	"os"
	"sync"
	"text/template"
	"time"

	"github.com/Zacky3181V/wireable/allocator"
	clientv3 "go.etcd.io/etcd/client/v3"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	serverPrivateKey   wgtypes.Key
	serverPublicKey    wgtypes.Key
	privateKeyFile     = "server_private.key"
	wasKeyGeneratedNow bool
	ipHeap             allocator.IPHeap
	etcdClient *clientv3.Client
	once               sync.Once
)

func init() {
	var err error

	serverPrivateKey, serverPublicKey, wasKeyGeneratedNow, err = loadOrGenerateServerKeys()
	if err != nil {
		log.Fatalf("Failed to initialize WireGuard server keys: %v", err)
	}
	log.Println("WireGuard server keys initialized.")

	if wasKeyGeneratedNow {
		log.Println("New WireGuard private key generated. Creating fresh server config.")
		writeInitialPeersFile(serverPrivateKey.String())
	} else {
		log.Println("Using existing WireGuard private key. Checking if config file is present.")

		if _, err := os.Stat("peers.conf"); os.IsNotExist(err) {
			log.Println("peers.conf does not exist. Creating it now.")
			writeInitialPeersFile(serverPrivateKey.String())
		} else if err != nil {
			log.Fatalf("Error checking peers.conf: %v", err)
		} else {
			log.Println("Config file found. All good.")
		}
	}

	
}

func InitEtcdAndHeap(ctx context.Context) error {
	var err error
	once.Do(func() {
		etcdClient, err = clientv3.New(clientv3.Config{
			Endpoints:   []string{os.Getenv("ETCD_ENDPOINT")},
			DialTimeout: 5 * time.Second,
		})
		if err != nil {
			return
		}
		log.Println("Connected to etcd")

		availableIPs, err := allocator.LoadAvailableIPs(ctx, etcdClient)
		if err != nil {
			log.Fatalf("Failed to load available IPs: %v", err)
		}
		log.Printf("Loaded available IPs from etcd")

		ipHeap = allocator.IPHeap(availableIPs)
		heap.Init(&ipHeap)
		log.Println("Initialized IP Heap")
	})
	return err
}

func GetEtcdClient() *clientv3.Client {
	return etcdClient
}

func GetIPHeap() *allocator.IPHeap {
	return &ipHeap
}

func GetServerPublicKey() string {
	return serverPublicKey.String()
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
	if err != nil {
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
