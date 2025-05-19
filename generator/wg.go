package generator

import (
	"bytes"
	"context"
	"os"
	"text/template"

	"github.com/Zacky3181V/wireable/config"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var tracer = otel.Tracer("wireguard-tracer")

type ConfigData struct {
	PrivateKey      string
	Address         string
	ServerPublicKey string
}

func generateConfigFromTemplate(ctx context.Context, data ConfigData) (string, error) {
	ctx, span := tracer.Start(ctx, "generateConfigFromTemplate")
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

	ctx, span := tracer.Start(ctx, "generateWireGuardKeys")
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

	configTemplate, err := generateConfigFromTemplate(ctx, ConfigData{
		PrivateKey:      privateKey,
		Address:         ip,
		ServerPublicKey: serverPublicKey,
	})

	if err != nil {
		span.RecordError(err)
		c.JSON(500, gin.H{"error": "Failed to generate config"})
	}

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

	// Read the peer template
	tmplBytes, err := os.ReadFile("./templates/peer.conf")
	if err != nil {
		span.RecordError(err)
		return err
	}

	// Parse the template
	tmpl, err := template.New("peer").Parse(string(tmplBytes))
	if err != nil {
		span.RecordError(err)
		return err
	}

	// Prepare the data for the template
	data := struct {
		PublicKey string
		Ip        string
	}{
		PublicKey: publicKey,
		Ip:        ip,
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		span.RecordError(err)
		return err
	}

	formatted := "\n" + buf.String() + "\n"

	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		span.RecordError(err)
		return err
	}
	defer file.Close()

	if _, err := file.WriteString(formatted); err != nil {
		span.RecordError(err)
		return err
	}

	return nil
}
