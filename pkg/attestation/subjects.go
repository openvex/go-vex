// Copyright 2026 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/google/go-containerregistry/pkg/crane"
	intoto "github.com/in-toto/attestation/go/v1"
	purl "github.com/package-url/packageurl-go"

	"github.com/openvex/go-vex/pkg/vex"
)

// resolveOCIDigest looks up the manifest digest of an image reference.
// It is a package-level variable so tests can stub registry I/O.
var resolveOCIDigest = func(ref string) (string, error) {
	return crane.Digest(ref)
}

// importProductsStrict walks every product in doc and appends a corresponding
// in-toto subject to att, aborting on the first per-product failure.
func importProductsStrict(att *Attestation, doc *vex.VEX) error {
	var firstErr error
	walkProductsForImport(att, doc, func(err error) bool {
		firstErr = err
		return false
	})
	return firstErr
}

// importProductsBestEffort is the lenient counterpart to importProductsStrict:
// failures resolving individual products are logged via slog and skipped.
func importProductsBestEffort(att *Attestation, doc *vex.VEX) {
	walkProductsForImport(att, doc, func(err error) bool {
		slog.Warn("skipping product in attestation subjects", "error", err.Error())
		return true
	})
}

// walkProductsForImport iterates the products in doc, appending one subject
// per attestable product to att. Conversion rules:
//
//   - For OCI purls (pkg:oci/... or pkg:/oci/...), the original purl is
//     recorded in the resource descriptor's Uri field, the derived image
//     reference goes in Name, and the digest goes in Digest. If the purl
//     does not carry a digest, it is fetched via crane.Digest.
//   - All other products are imported only if they carry at least one hash
//     whose algorithm has an in-toto equivalent; algorithm names are mapped
//     via vex.Algorithm.ToInToto.
//
// onError is invoked for each per-product failure; if it returns false,
// iteration stops.
func walkProductsForImport(att *Attestation, doc *vex.VEX, onError func(error) bool) {
	if doc == nil {
		return
	}

	seen := map[string]struct{}{}
	for i := range doc.Statements {
		for j := range doc.Statements[i].Products {
			p := &doc.Statements[i].Products[j]
			sub, key, err := productToSubject(p)
			if err != nil {
				if !onError(err) {
					return
				}
				continue
			}
			if sub == nil {
				continue
			}
			if _, dup := seen[key]; dup {
				continue
			}
			seen[key] = struct{}{}
			att.Subject = append(att.Subject, sub)
		}
	}
}

// productToSubject converts a VEX product into an in-toto resource
// descriptor. Returns (nil, "", nil) when the product is not attestable
// (e.g., non-OCI product without hashes).
//
// OCI purl detection prefers a PURL entry in the product's identifiers
// over the product's main ID — the identifiers map is the canonical home
// for software identifiers, with the main ID often being a generic IRI.
func productToSubject(p *vex.Product) (*intoto.ResourceDescriptor, string, error) {
	if ociPurl := findOCIPurl(p); ociPurl != "" {
		sub, err := ociPurlToSubject(ociPurl)
		if err != nil {
			return nil, "", err
		}
		return sub, ociPurl, nil
	}

	digest := convertHashes(p.Hashes)
	if len(digest) == 0 {
		return nil, "", nil
	}

	id := productPrimaryID(p)
	sub := &intoto.ResourceDescriptor{
		Name:   id,
		Digest: digest,
	}
	key := id
	if key == "" {
		for a, h := range digest {
			key = a + ":" + h
			break
		}
	}
	return sub, key, nil
}

// findOCIPurl returns the OCI purl for a product, preferring the PURL entry
// in the identifiers map and falling back to the main ID. Returns "" when
// neither is an OCI purl.
func findOCIPurl(p *vex.Product) string {
	if id, ok := p.Identifiers[vex.PURL]; ok && isOCIPurl(id) {
		return id
	}
	if isOCIPurl(p.ID) {
		return p.ID
	}
	return ""
}

// productPrimaryID picks the primary identifier for a product: ID first,
// then the PURL identifier, then any other identifier.
func productPrimaryID(p *vex.Product) string {
	if p.ID != "" {
		return p.ID
	}
	if id, ok := p.Identifiers[vex.PURL]; ok {
		return id
	}
	for _, id := range p.Identifiers {
		return id
	}
	return ""
}

func isOCIPurl(id string) bool {
	return strings.HasPrefix(id, "pkg:oci/") || strings.HasPrefix(id, "pkg:/oci/")
}

// ociPurlToSubject parses an OCI purl and returns a resource descriptor
// with Uri set to the original purl, Name set to the derived image
// reference, and Digest set to the resolved digest. If the purl does not
// carry a digest, it is looked up via crane.Digest.
func ociPurlToSubject(original string) (*intoto.ResourceDescriptor, error) {
	p, err := purl.FromString(original)
	if err != nil {
		return nil, fmt.Errorf("parsing OCI purl %q: %w", original, err)
	}

	qs := p.Qualifiers.Map()
	var ref string
	if r, ok := qs["repository_url"]; ok {
		ref = strings.TrimSuffix(r, "/")
	} else {
		ref = p.Name
	}

	var algo, hexDigest string
	if p.Version != "" {
		ref += "@" + p.Version
		if parts := strings.SplitN(p.Version, ":", 2); len(parts) == 2 {
			algo, hexDigest = parts[0], parts[1]
		}
	} else if tag, ok := qs["tag"]; ok {
		ref += ":" + tag
	}

	if hexDigest == "" {
		looked, err := resolveOCIDigest(ref)
		if err != nil {
			return nil, fmt.Errorf("resolving digest for %s: %w", ref, err)
		}
		parts := strings.SplitN(looked, ":", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unexpected digest format %q from registry", looked)
		}
		algo, hexDigest = parts[0], parts[1]
	}

	return &intoto.ResourceDescriptor{
		Uri:    original,
		Name:   ref,
		Digest: map[string]string{algo: hexDigest},
	}, nil
}

// convertHashes maps a vex.Hash map from OpenVEX algorithm names to the
// in-toto names. Algorithms without an in-toto equivalent are dropped.
func convertHashes(h map[vex.Algorithm]vex.Hash) map[string]string {
	if len(h) == 0 {
		return nil
	}
	out := map[string]string{}
	for algo, hash := range h {
		intotoName := algo.ToInToto()
		if intotoName == "" {
			continue
		}
		out[intotoName] = string(hash)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
