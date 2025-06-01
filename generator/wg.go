package generator

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"text/template"

	"github.com/Zacky3181V/wireable/allocator"
	"github.com/Zacky3181V/wireable/config"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var tracer = otel.Tracer("wireguard-tracer")

type ConfigData struct {
	PrivateKey      string
	Address         string
	ServerPublicKey string
}

func generateConfigFromTemplate(ctx context.Context, data ConfigData) (string, error) {
	_, span := tracer.Start(ctx, "generateConfigFromTemplate")
	defer span.End()
	tmplBytes, err := os.ReadFile("./templates/client_template.conf")
	if err != nil {
		return "", err
	}

	tmpl, err := template.New("wg").Parse(string(tmplBytes))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}

	return buf.String(), nil
}

func generateWireGuardKeys(ctx context.Context) (string, string, error) {

	_, span := tracer.Start(ctx, "generateWireGuardKeys")
	defer span.End()

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
	if err != nil {
		span.RecordError(err)
		c.JSON(500, gin.H{"error": "Failed to generate keys"})
		return
	}

	ip, err := allocator.AllocateIP(ctx, config.GetEtcdClient(), config.GetIPHeap(), publicKey)

	if err != nil {
		log.Fatalf("Failed to allocate IP")
		return
	}

	serverPublicKey := config.GetServerPublicKey()

	configTemplate, err := generateConfigFromTemplate(ctx, ConfigData{
		PrivateKey:      privateKey,
		Address:         ip.String(),
		ServerPublicKey: serverPublicKey,
	})

	if err != nil {
		span.RecordError(err)
		c.JSON(500, gin.H{"error": "Failed to generate config"})
		return
	}
	err = addWireguardPeer(ctx, ip.String(), publicKey)
	if err != nil {
		span.RecordError(err)
		c.JSON(500, gin.H{"error": "Failed to add wireguard peer"})
		return
	}

	c.Header("Content-Type", "text/plain")
	c.String(200, configTemplate)

}

func addWireguardPeer(ctx context.Context, ip string, publicKey string) error {
	_, span := tracer.Start(ctx, "addWireguardPeer")
	interfaceName := "peers"
	allowedIPs := fmt.Sprintf("%s/32", ip)

	cmd := exec.Command(
		"wg", "set", interfaceName,
		"peer", publicKey,
		"allowed-ips", allowedIPs,
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		span.RecordError(err)
		return fmt.Errorf("failed to add WireGuard peer: %v\nOutput: %s", err, string(output))
	}

	return nil
}
