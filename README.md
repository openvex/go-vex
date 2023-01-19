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
		Vulnerability: "CVE-2023-12345",

		// ... add an image as product:
		Products: []string{
			"pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb",
		},

		// ... specify optional subcomponents:
		Subcomponents: []string{
			"pkg:apk/alpine/git@2.38.1-r0?arch=x86_64",
			"pkg:apk/alpine/git@2.38.1-r0?arch=ppc64le",
		},

		// ... choose one of the VEX status labels:
		Status: vex.StatusNotAffected,

		// ... finally, a machine-readable justification and optional statement:
		Justification:   vex.InlineMitigationsAlreadyExist,
		ImpactStatement: "Included git is mitigated against CVE-2023-12345 !",
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
  "@context": "https://openvex.dev/ns",
  "@id": "https://openvex.dev/docs/public/vex-a06f9de1ad1b1e555a33b2d0c1e7e6ecc4dc1800ff457c61ea09d8e97670d2a3",
  "author": "Wolfi J. Inkinson",
  "role": "Senior VEXing Engineer",
  "timestamp": "2023-01-09T21:23:03.579712389-06:00",
  "version": "1",
  "statements": [
    {
      "vulnerability": "CVE-2023-12345",
      "products": [
        "pkg:oci/git@sha256:23a264e6e429852221a963e9f17338ba3f5796dc7086e46439a6f4482cf6e0cb"
      ],
      "subcomponents": [
        "pkg:apk/alpine/git@2.38.1-r0?arch=x86_64",
        "pkg:apk/alpine/git@2.38.1-r0?arch=ppc64le"
      ],
      "status": "not_affected",
      "justification": "inline_mitigations_already_exist",
      "impact_statement": "Included git is mitigated against CVE-2023-12345 !"
    }
  ]
}

```
