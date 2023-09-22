# go-vex

Go library for generating, consuming, and operating on VEX documents

[![Build Status](https://github.com/openvex/go-vex/actions/workflows/ci-build-test.yaml/badge.svg?branch=main)](https://github.com/openvex/go-vex/actions/workflows/ci-build-test.yaml?query=branch%3Amain)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/openvex/go-vex)](https://pkg.go.dev/github.com/openvex/go-vex)
[![Go Report Card](https://goreportcard.com/badge/github.com/openvex/go-vex)](https://goreportcard.com/report/github.com/openvex/go-vex)

This repository contains the OpenVEX Go source code. This module lets
authors create, modify and manage VEX documents.

The full documentation for this module can be found at
https://pkg.go.dev/github.com/openvex/go-vex.

For more information about the OpenVEX specification implemented by this module, check out the
[OpenVEX specification](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md).

## Installing

Run `go get` to install the latest version of the library.

```console
go get -u github.com/openvex/go-vex@latest
```

## Example Usage: Generate a VEX Document

The following is a simple example showing how to generate a VEX document:

```golang
package main

import (
	"os"

	"github.com/openvex/go-vex/pkg/vex"
)

func main() {
	// Create new VEX document
	doc := vex.New()

	// Define the documenmt author
	doc.Author = "Wolfi J. Inkinson"
	doc.AuthorRole = "Senior VEXing Engineer"

	// Here, we add an impact statement. The core of VEX. We will inform
	// that our git image is not affected by CVE-2023-12345 and why:
	doc.Statements = append(doc.Statements, vex.Statement{
		// ... define the vulnerability:
		Vulnerability: vex.Vulnerability{
			ID:          "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
			Name:        "CVE-2021-44228",
			Description: "Remote code injection in Log4j",
			Aliases: []vex.VulnerabilityID{
				vex.VulnerabilityID("GHSA-jfh8-c2jp-5v3q"),
			},
		},

		// ... add an image as product:
		Products: []vex.Product{
			{
				Component: vex.Component{
					ID: "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
					Identifiers: map[vex.IdentifierType]string{
						vex.PURL: "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
					},
					Hashes: map[vex.Algorithm]vex.Hash{
						vex.SHA256: vex.Hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
					},
				},

				// ... specify optional subcomponents:
				// Subcomponents: []vex.Subcomponent{},
			},
			// "pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb",
		},

		// ... choose one of the VEX status labels:
		Status: vex.StatusNotAffected,

		// ... finally, a machine-readable justification and optional statement:
		Justification:   vex.VulnerableCodeNotInExecutePath,
		ImpactStatement: "Spring Boot users are only affected by this vulnerability if they ...",
	})

	// Generate a canonical identifier for the VEX document:
	doc.GenerateCanonicalID()

	// Output the document to stdout:
	doc.ToJSON(os.Stdout)
}

```
Running this example renders the following simple VEX document:

```json
{
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://openvex.dev/docs/public/vex-6ccf08fbf67f1489f201bb2b79a024b55d2ce07763098c78822f2f25283703d8",
  "author": "Wolfi J. Inkinson",
  "role": "Senior VEXing Engineer",
  "timestamp": "2023-09-21T15:32:30.728569-05:00",
  "version": 1,
  "statements": [
    {
      "vulnerability": {
        "@id": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
        "name": "CVE-2021-44228",
        "description": "Remote code injection in Log4j",
        "aliases": [
          "GHSA-jfh8-c2jp-5v3q"
        ]
      },
      "products": [
        {
          "@id": "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3",
          "hashes": {
            "sha-256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
          },
          "identifiers": {
            "purl": "pkg:maven/org.springframework.boot/spring-boot@2.6.0-M3"
          }
        }
      ],
      "status": "not_affected",
      "justification": "vulnerable_code_not_in_execute_path",
      "impact_statement": "Spring Boot users are only affected by this vulnerability if they ..."
    }
  ]
}
```
