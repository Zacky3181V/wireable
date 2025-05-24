package main

import (
	"container/heap"
	"context"
	"log"
	"os"
	"time"

	"github.com/joho/godotenv"
	"go.etcd.io/etcd/client/v3"

	"github.com/Zacky3181V/wireable/allocator"
	"github.com/Zacky3181V/wireable/authentication"
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
// @host localhost:8080
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @BasePath /api/v1/
func main() {
	ctx := context.Background()

	cli, err := clientv3.New(clientv3.Config{
		Endpoints:   []string{"localhost:2379"}, // etcd endpoint
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		log.Fatalf("Failed to connect etcd: %v", err)
	}
	defer cli.Close()
	log.Printf("Connected to etcd")

	availableIPs, err := allocator.LoadAvailableIPs(ctx, cli)
	if err != nil {
		log.Fatalf("Failed to load available IPs: %v", err)
	}
	log.Printf("Loaded available IPs")

	ipHeap := allocator.IPHeap(availableIPs)
	heap.Init(&ipHeap)
	log.Printf("Initizalied Heap")

	go allocator.WatchAvailableIPs(ctx, cli, &ipHeap)
	log.Printf("Watching for new available IPs added to etcd")

	ip, err := allocator.AllocateIP(ctx, cli, &ipHeap, "node-1")
	if err!=nil{
		log.Fatalf("Failed to allocate IP")
	}
	log.Printf("Allocated IP %v", ip)
	time.Sleep(10 * time.Second)

	err = allocator.ReleaseIP(ctx, cli, ip)
	if err != nil {
		log.Fatalf("Failed to release IP: %v", err)
	}
	log.Printf("Released IP: %s\n", ip.String())


	if err != nil {
		log.Fatalf("Failed to allocate IP: %v", err)
	}
	log.Printf("Allocated IP: %s\n", ip.String())

	if enableTracing {
		cleanup := initTracer()
		defer cleanup(context.Background())
	}

	_, err = vaultclient.InitClient()
	if err!=nil{
		log.Fatalf("Failed to initialize Vault client %v", err)
	}

	log.Println("Hello World from Wireable!")


	r := setupRouter()

	r.Run(":8081")
}
