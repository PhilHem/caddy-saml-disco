package main

import (
	"fmt"
	"os"

	"github.com/philiph/caddy-saml-disco/internal/adapters/driven/metadata"
)

func main() {
	data, err := os.ReadFile("testdata/dfn-aai-sample.xml")
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		os.Exit(1)
	}

	idps, _, err := metadata.ParseMetadata(data)
	if err != nil {
		fmt.Printf("Error parsing metadata: %v\n", err)
		os.Exit(1)
	}

	// Check FU Berlin (has R&S + SIRTFI)
	found := false
	for _, idp := range idps {
		if idp.EntityID == "https://identity.fu-berlin.de/idp-fub" {
			found = true
			hasRS := false
			hasSIRTFI := false
			for _, cat := range idp.EntityCategories {
				if cat == "http://refeds.org/category/research-and-scholarship" {
					hasRS = true
				}
			}
			for _, cert := range idp.AssuranceCertifications {
				if cert == "https://refeds.org/sirtfi" {
					hasSIRTFI = true
				}
			}
			if !hasRS {
				fmt.Printf("FAIL: FU Berlin missing R&S category\n")
				os.Exit(1)
			}
			if !hasSIRTFI {
				fmt.Printf("FAIL: FU Berlin missing SIRTFI certification\n")
				os.Exit(1)
			}
			fmt.Printf("PASS: FU Berlin has R&S and SIRTFI\n")
		}
	}

	if !found {
		fmt.Printf("FAIL: FU Berlin not found\n")
		os.Exit(1)
	}

	fmt.Printf("SUCCESS: EntityAttributes parsing works correctly\n")
}
