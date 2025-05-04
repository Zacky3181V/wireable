package generator

import (
	"context"
	"fmt"
	"os"

	"github.com/Zacky3181V/wireable/config"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var tracer = otel.Tracer("wireguard-tracer")

func generateWireGuardKeys(ctx context.Context) (string, string, error) {

	ctx, span := tracer.Start(ctx, "generateWireGuard keys")
	defer span.End()

	span.SetAttributes(attribute.Key("operations").String("generateWireGuardKeys"))

	privateKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		span.RecordError(err)
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

	ctx, span := tracer.Start(c.Request.Context(), "WireGuardHandler")
	defer span.End() 

	privateKey, publicKey, err := generateWireGuardKeys(ctx)
	wgAllocator := config.GetAllocator()
	if err != nil {
		span.RecordError(err)
		c.JSON(500, gin.H{"error": "Failed to generate keys"})
		return
	}

	ip, err := wgAllocator.Allocate()
	if err != nil {
		span.RecordError(err)
		c.JSON(500, gin.H{"error": "No IPs available"})
		return
	}

	if err := appendPeerToFile(ctx, "peers.conf", publicKey, ip); err != nil {
		span.RecordError(err)
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

func appendPeerToFile(ctx context.Context, filename, publicKey, ip string) error {

	ctx, span := tracer.Start(ctx, "appendPeerToFile")
	defer span.End()

	span.SetAttributes(
		attribute.Key("filename").String(filename),
		attribute.Key("publicKey").String(publicKey),
		attribute.Key("ip").String(ip),
	)

	entry := fmt.Sprintf(`
[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, publicKey, ip)

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		span.RecordError(err)
		return err
	}
	defer file.Close()

	_, err = file.WriteString(entry)

	if err != nil {
		span.RecordError(err)
	}
	return err
}
