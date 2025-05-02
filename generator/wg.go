package generator

import (
	"fmt"
	"os"

	"github.com/Zacky3181V/wireable/config"
	"github.com/gin-gonic/gin"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func generateWireGuardKeys() (string, string, error) {
	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", err
	}

	publicKey := privateKey.PublicKey()

	return privateKey.String(), publicKey.String(), nil
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
	wgAllocator := config.GetAllocator()
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to generate keys"})
		return
	}

	ip, err := wgAllocator.Allocate()
	if err != nil {
		c.JSON(500, gin.H{"error": "No IPs available"})
		return
	}

	if err := appendPeerToFile("peers.conf", publicKey, ip); err != nil {
		c.JSON(500, gin.H{"error": "Failed to update peers.conf"})
		return
	}

	serverPublicKey := config.GetServerPublicKey()

	configTemplate := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
DNS = 1.1.1.1

[Peer]
PublicKey = %s
Endpoint = example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`, privateKey, ip, serverPublicKey)

	c.Header("Content-Type", "text/plain")
	c.String(200, configTemplate)
}

func appendPeerToFile(filename, publicKey, ip string) error {
	entry := fmt.Sprintf(`
[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, publicKey, ip)

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()

	_, err = file.WriteString(entry)
	return err
}
