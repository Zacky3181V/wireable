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

	JWTSecret string
	Username  string
	Password  string

	secretsOnce sync.Once
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

func InitSecrets() error {
	var err error
	secretsOnce.Do(func() {
		vc, e := InitClient()
		if e != nil {
			err = e
			return
		}

		mountPath := os.Getenv("MOUNT_PATH")
		jwtSecretPath := os.Getenv("JWT_SECRET")
		jwtSecretKey := os.Getenv("JWT_SECRET_KEY")
		credsSecretPath := os.Getenv("CREDS_SECRET")
		usernameKey := os.Getenv("USERNAME_SECRET_KEY")
		passwordKey := os.Getenv("PASSWORD_SECRET_KEY")

		if mountPath == "" || jwtSecretPath == "" || jwtSecretKey == "" ||
			credsSecretPath == "" || usernameKey == "" || passwordKey == "" {
			err =  logError("One or more required environment variables are empty")
			return
		}

		JWTSecret = ProcessSecret(vc, mountPath, jwtSecretPath, jwtSecretKey)
		Username = ProcessSecret(vc, mountPath, credsSecretPath, usernameKey)
		Password = ProcessSecret(vc, mountPath, credsSecretPath, passwordKey)

		if JWTSecret == "" || Username == "" || Password == "" {
			err = logError("Failed to load one or more secrets from Vault")
			return
		}
	})
	return err
}

func logError(msg string) error {
	log.Println(msg)
	return &customError{msg}
}

type customError struct {
	msg string
}

func (e *customError) Error() string {
	return e.msg
}
