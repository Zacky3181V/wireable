package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"

	"github.com/Zacky3181V/wireable/allocator"
	"github.com/Zacky3181V/wireable/authentication"
	"github.com/Zacky3181V/wireable/config"
	"github.com/Zacky3181V/wireable/generator"
	"github.com/Zacky3181V/wireable/vaultclient"
	"github.com/gin-gonic/gin"
	"google.golang.org/grpc/credentials"

	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"

	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"

	//"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	docs "github.com/Zacky3181V/wireable/docs"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

var (
	serviceName   string
	collectorURL  string
	insecure      string
	enableTracing bool
)

func init() {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	serviceName = os.Getenv("SERVICE_NAME")
	collectorURL = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	insecure = os.Getenv("INSECURE_MODE")

	enableTracing = os.Getenv("ENABLE_TRACING") == "true"
	if enableTracing {
		log.Println("Tracing enabled")
	} else {
		log.Println("No tracing")
	}
}

func initTracer() func(context.Context) error {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	serviceName = os.Getenv("SERVICE_NAME")
	collectorURL = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	insecure = os.Getenv("INSECURE_MODE")

	if serviceName == "" {
		log.Fatal("ERROR: SERVICE_NAME is not set")
	}
	if collectorURL == "" {
		log.Fatal("ERROR: OTEL_EXPORTER_OTLP_ENDPOINT is not set")
	}

	secureOption := otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, ""))
	if len(insecure) > 0 {
		secureOption = otlptracegrpc.WithInsecure()
	}

	exporter, err := otlptrace.New(
		context.Background(),
		otlptracegrpc.NewClient(
			secureOption,
			otlptracegrpc.WithEndpoint(collectorURL),
		),
	)

	if err != nil {
		log.Fatal(err)
	}
	resources, err := resource.New(
		context.Background(),
		resource.WithAttributes(
			attribute.String("service.name", serviceName),
			attribute.String("library.language", "go"),
		),
	)
	if err != nil {
		log.Printf("Could not set resources: %v", err)
	}

	otel.SetTracerProvider(
		sdktrace.NewTracerProvider(
			sdktrace.WithSampler(sdktrace.AlwaysSample()),
			sdktrace.WithBatcher(exporter),
			sdktrace.WithResource(resources),
		),
	)
	return exporter.Shutdown
}

func setupRouter() *gin.Engine {

	r := gin.Default()
	r.Use(otelgin.Middleware(serviceName))
	docs.SwaggerInfo.BasePath = "/api/v1"
	v1 := r.Group("/api/v1")
	{
		login := v1.Group("/authentication")
		{

			login.POST("/login", authentication.LoginHandler)
		}
	}

	protected := r.Group(docs.SwaggerInfo.BasePath)
	{
		protected.Use(authentication.JWTMiddleware())
		protected.GET("/generate", generator.WireGuardHandler)
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	return r
}

// @title Wireable
// @version 1.0
// @description Automation of Zero-Trust connection for Edge Locations
// @host localhost:8081
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @BasePath /api/v1/
func main() {
	var err error
	ctx := context.Background()

	if err := config.InitEtcdAndHeap(ctx); err != nil {
		log.Fatalf("Failed to initialize etcd and IP heap: %v", err)
	}

	go allocator.WatchAvailableIPs(ctx, config.GetEtcdClient(), config.GetIPHeap())
	log.Printf("Watching for new available IPs added to etcd")

	if enableTracing {
		cleanup := initTracer()
		defer cleanup(context.Background())
	}

	_, err = vaultclient.InitClient()
	if err != nil {
		log.Fatalf("Failed to initialize Vault client %v", err)
	}

	err = vaultclient.InitSecrets()
	if err != nil {
		log.Fatalf("Failed to load secrets: %v", err)
	}
	log.Println("Secrets loaded")

	cmd := exec.Command("cp", "peers.conf", "/etc/wireguard/peers.conf")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to move WireGuard config to /etc/wireguard: %v\nOutput: %s", err, output)
	}

	cmdUp := exec.Command("wg-quick", "up", "peers")
	output, err = cmdUp.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to move WireGuard config to /etc/wireguard: %v\nOutput: %s", err, output)
	}
	log.Println("WireGuard interface is up")
	log.Println("Hello World from Wireable!")

	r := setupRouter()

	srv := &http.Server{
		Addr:    ":8080",
		Handler: r,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Gin server error: %v", err)
		}
	}()

	// Graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Give server 5 seconds to shut down
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	// Bring down WireGuard
	cmdDown := exec.Command("wg-quick", "down", "peers")
	if err := cmdDown.Run(); err != nil {
		log.Printf("Failed to bring down WireGuard interface: %v", err)
	} else {
		log.Println("WireGuard interface brought down successfully.")
	}

	
}
