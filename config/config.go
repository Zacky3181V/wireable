package config

import (
	"log"

	"github.com/Zacky3181V/wireable/allocator"
)

var wgAllocator *allocator.IPAllocator

func init() {
	var err error
	wgAllocator, err = allocator.NewIPAllocator("10.0.0.0/24")
	if err != nil {
		log.Fatalf("Failed to initialize IPAllocator: %v", err)
	}
	log.Println("IPAllocator initialized successfully.")
}

func GetAllocator() *allocator.IPAllocator {
	return wgAllocator
}