package generator

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/curve25519"
)

func generateWireGuardKeys() (string, string, error) {
	var privateKey [32]byte
	_, err := rand.Read(privateKey[:])
	if err != nil {
		return "", "", err
	}

	privateKey[0] &= 248
	privateKey[31] &= 127
	privateKey[31] |= 64

	var publicKey [32]byte
	curve25519.ScalarBaseMult(&publicKey, &privateKey)

	privateKeyB64 := base64.StdEncoding.EncodeToString(privateKey[:])
	publicKeyB64 := base64.StdEncoding.EncodeToString(publicKey[:])

	return privateKeyB64, publicKeyB64, nil
}

// @Summary Generate Wireguard configuration
// @Description Generates a private and public key pair for WireGuard and returns a configuration template.
// @ID wireguard-config
// @Accept json
// @Produce text/plain
// @Security BearerAuth
// @Success 200 {string} string "WireGuard Configuration Template"
// @Failure 500
// @Router /generate [get]
func WireGuardHandler(c *gin.Context) {
	privateKey, publicKey, err := generateWireGuardKeys()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate keys"})
		return
	}

	configTemplate := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.0.0.2/24
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, privateKey, publicKey)

	c.Header("Content-Type", "text/plain")
	c.String(200, configTemplate)
}
