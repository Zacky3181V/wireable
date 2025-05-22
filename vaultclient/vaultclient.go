package vaultclient

import (
	"context"
	"log"
	"os"
	"sync"

	"github.com/hashicorp/vault/api"
)

var (
	client     *api.Client
	clientOnce sync.Once
)

func InitClient() (*api.Client, error) {
	var err error
	clientOnce.Do(func() {
		config := &api.Config{
			Address: os.Getenv("VAULT_ENDPOINT"),
		}
		client, err = api.NewClient(config)
		if err != nil {
			log.Printf("Error initializing Vault client: %v", err)
			return
		}
		client.SetToken(os.Getenv("VAULT_TOKEN"))
	})
	return client, err
}

func GetClient() *api.Client {
	if client == nil {
		log.Fatal("Vault client not initialized. Call InitClient first.")
		return nil
	}
	return client
}

func ProcessSecret(vc *api.Client, mountPath string, secretName string, key string) string {
	
	if vc == nil {
        log.Println("Vault client is nil")
        return ""
    }

	ctx := context.Background()

	secret, err := vc.KVv2(mountPath).Get(ctx, secretName)

	if err!=nil{
		log.Printf("Error reading secret %s/%s: %v", mountPath, secretName, err)
		return ""
	}
	
	if val, ok := secret.Data[key]; ok {
        if strVal, ok := val.(string); ok {
            return strVal
        } else {
            log.Printf("Value for key '%s' is not a string", key)
        }
    } else {
        log.Printf("Key '%s' not found in secret data", key)
    }

    return ""
}
