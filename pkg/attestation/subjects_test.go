// Copyright 2026 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"errors"
	"testing"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/vex"
)

// failResolver returns an ImageDigestResolver that fails the test if called.
// Use it when the test expects no digest lookups.
func failResolver(t *testing.T) ImageDigestResolver {
	t.Helper()
	return ImageDigestResolver(func(string) (string, error) {
		t.Fatalf("ImageDigestResolver should not be called")
		return "", nil
	})
}

func vexWithProducts(prods ...vex.Product) vex.VEX {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	return vex.VEX{
		Metadata: vex.Metadata{
			Context:   vex.ContextLocator(),
			ID:        "https://openvex.dev/docs/test/import",
			Author:    "mailto:test@example.com",
			Timestamp: &ts,
			Version:   1,
		},
		Statements: []vex.Statement{
			{
				Vulnerability: vex.Vulnerability{Name: "CVE-2024-1234"},
				Status:        vex.StatusNotAffected,
				Justification: vex.VulnerableCodeNotPresent,
				Timestamp:     &ts,
				Products:      prods,
			},
		},
	}
}

func TestImportOCIPurlWithEmbeddedDigest(t *testing.T) {
	purl := "pkg:oci/nginx@sha256:abc123def456"
	doc := vexWithProducts(vex.Product{Component: vex.Component{ID: purl}})

	// No resolver passed: the embedded digest means none is needed.
	att := New(WithPredicate(&doc), WithImageDigestResolver(failResolver(t)))

	require.Len(t, att.Subject, 1)
	s := att.Subject[0]
	require.Equal(t, purl, s.GetUri(), "original purl must be in Uri")
	require.Equal(t, "nginx@sha256:abc123def456", s.GetName(), "image ref must be in Name")
	require.Equal(t, map[string]string{"sha256": "abc123def456"}, s.GetDigest())
}

func TestImportOCIPurlWithRepositoryURLAndTag(t *testing.T) {
	// No digest in purl: resolver fills it in.
	resolver := ImageDigestResolver(func(ref string) (string, error) {
		require.Equal(t, "ghcr.io/myorg/app:1.2.3", ref)
		return "sha256:cafebabe", nil
	})

	purl := "pkg:oci/app?repository_url=ghcr.io/myorg/app&tag=1.2.3"
	doc := vexWithProducts(vex.Product{Component: vex.Component{ID: purl}})
	att := New(WithPredicate(&doc), WithImageDigestResolver(resolver))

	require.Len(t, att.Subject, 1)
	s := att.Subject[0]
	require.Equal(t, purl, s.GetUri())
	require.Equal(t, "ghcr.io/myorg/app:1.2.3", s.GetName())
	require.Equal(t, map[string]string{"sha256": "cafebabe"}, s.GetDigest())
}

func TestImportOCIPurlFromIdentifiers(t *testing.T) {
	ociPurl := "pkg:oci/nginx@sha256:abc123"
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{
			ID: "https://example.com/some-iri",
			Identifiers: map[vex.IdentifierType]string{
				vex.PURL: ociPurl,
			},
		},
	})

	att := New(WithPredicate(&doc), WithImageDigestResolver(failResolver(t)))
	require.Len(t, att.Subject, 1)
	s := att.Subject[0]
	require.Equal(t, ociPurl, s.GetUri())
	require.Equal(t, "nginx@sha256:abc123", s.GetName())
}

func TestImportOCIPurlIdentifiersPreferredOverID(t *testing.T) {
	idPurl := "pkg:oci/old@sha256:111"
	identPurl := "pkg:oci/new@sha256:222"
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{
			ID: idPurl,
			Identifiers: map[vex.IdentifierType]string{
				vex.PURL: identPurl,
			},
		},
	})

	att := New(WithPredicate(&doc), WithImageDigestResolver(failResolver(t)))
	require.Len(t, att.Subject, 1)
	require.Equal(t, identPurl, att.Subject[0].GetUri(), "Identifiers[PURL] must take precedence over ID")
}

func TestImportOCIPurlFallsBackToIDWhenIdentifierNotOCI(t *testing.T) {
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{
			ID: "pkg:oci/app@sha256:abc",
			Identifiers: map[vex.IdentifierType]string{
				vex.PURL: "pkg:npm/lodash@1.0.0",
			},
		},
	})

	att := New(WithPredicate(&doc), WithImageDigestResolver(failResolver(t)))
	require.Len(t, att.Subject, 1)
	require.Equal(t, "pkg:oci/app@sha256:abc", att.Subject[0].GetUri())
}

func TestImportNonOCIWithHashes(t *testing.T) {
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{
			ID: "pkg:npm/lodash@4.17.21",
			Hashes: map[vex.Algorithm]vex.Hash{
				vex.SHA256: "deadbeef",
				vex.SHA512: "feedface",
			},
		},
	})

	// Non-OCI: resolver is not consulted.
	att := New(WithPredicate(&doc))
	require.Len(t, att.Subject, 1)
	s := att.Subject[0]
	require.Equal(t, "pkg:npm/lodash@4.17.21", s.GetName())
	require.Equal(t, "deadbeef", s.GetDigest()["sha256"], "vex.SHA256 must map to in-toto sha256")
	require.Equal(t, "feedface", s.GetDigest()["sha512"], "vex.SHA512 must map to in-toto sha512")
}

func TestImportNonOCIWithoutHashesSkipped(t *testing.T) {
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{ID: "pkg:npm/lodash@4.17.21"},
	})
	att := New(WithPredicate(&doc))
	require.Empty(t, att.Subject)
}

func TestImportDropsUnmappableAlgorithm(t *testing.T) {
	// blake3 has no in-toto equivalent; product should be dropped entirely.
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{
			ID:     "pkg:generic/thing",
			Hashes: map[vex.Algorithm]vex.Hash{vex.BLAKE3: "abc"},
		},
	})
	att := New(WithPredicate(&doc))
	require.Empty(t, att.Subject)
}

func TestImportDefaultsOn(t *testing.T) {
	resolver := ImageDigestResolver(func(string) (string, error) { return "sha256:aaa", nil })
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{ID: "pkg:oci/app"},
	})
	// No WithImportProducts option — default should import.
	att := New(WithPredicate(&doc), WithImageDigestResolver(resolver))
	require.Len(t, att.Subject, 1)
}

func TestImportDisabled(t *testing.T) {
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{ID: "pkg:oci/nginx@sha256:abc"},
	})
	att := New(
		WithPredicate(&doc),
		WithImportProducts(false),
		WithImageDigestResolver(failResolver(t)),
	)
	require.Empty(t, att.Subject)
}

func TestImportDedupesAcrossStatements(t *testing.T) {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	stmt := func(cve string) vex.Statement {
		return vex.Statement{
			Vulnerability: vex.Vulnerability{Name: vex.VulnerabilityID(cve)},
			Status:        vex.StatusNotAffected,
			Justification: vex.VulnerableCodeNotPresent,
			Timestamp:     &ts,
			Products: []vex.Product{
				{Component: vex.Component{ID: "pkg:oci/nginx@sha256:abc"}},
			},
		}
	}
	doc := vex.VEX{
		Metadata: vex.Metadata{
			Context:   vex.ContextLocator(),
			ID:        "https://openvex.dev/docs/test/dup",
			Author:    "mailto:test@example.com",
			Timestamp: &ts,
			Version:   1,
		},
		Statements: []vex.Statement{stmt("CVE-1"), stmt("CVE-2")},
	}

	att := New(WithPredicate(&doc))
	require.Len(t, att.Subject, 1, "same product across statements must dedupe to one subject")
}

func TestNewWithErrorPropagatesResolverFailure(t *testing.T) {
	resolver := ImageDigestResolver(func(string) (string, error) {
		return "", errors.New("registry unreachable")
	})
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{ID: "pkg:oci/app"},
	})

	att, err := NewWithError(WithPredicate(&doc), WithImageDigestResolver(resolver))
	require.Error(t, err)
	require.Contains(t, err.Error(), "registry unreachable")
	require.NotNil(t, att)
}

func TestNewBestEffortSkipsOnResolverFailure(t *testing.T) {
	resolver := ImageDigestResolver(func(ref string) (string, error) {
		if ref == "broken" {
			return "", errors.New("boom")
		}
		return "sha256:aaa", nil
	})

	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	doc := vex.VEX{
		Metadata: vex.Metadata{
			Context:   vex.ContextLocator(),
			ID:        "https://openvex.dev/docs/test/skip",
			Author:    "mailto:test@example.com",
			Timestamp: &ts,
			Version:   1,
		},
		Statements: []vex.Statement{{
			Vulnerability: vex.Vulnerability{Name: "CVE-1"},
			Status:        vex.StatusNotAffected,
			Justification: vex.VulnerableCodeNotPresent,
			Timestamp:     &ts,
			Products: []vex.Product{
				{Component: vex.Component{ID: "pkg:oci/broken"}},
				{Component: vex.Component{ID: "pkg:oci/good@sha256:abc"}},
			},
		}},
	}

	att := New(WithPredicate(&doc), WithImageDigestResolver(resolver))
	// Broken one is skipped; the good one (with embedded digest) survives.
	require.Len(t, att.Subject, 1)
	require.Equal(t, "good@sha256:abc", att.Subject[0].GetName())
}

func TestImportPreservesExplicitSubjects(t *testing.T) {
	resolver := ImageDigestResolver(func(string) (string, error) { return "sha256:imported", nil })
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{ID: "pkg:oci/app"},
	})

	explicit := &intoto.ResourceDescriptor{
		Name:   "manually-added",
		Digest: map[string]string{"sha256": "manual"},
	}
	att := New(
		WithPredicate(&doc),
		WithSubjects(explicit),
		WithImageDigestResolver(resolver),
	)
	require.Len(t, att.Subject, 2, "explicit subjects must coexist with imported ones")
	require.Equal(t, "manually-added", att.Subject[0].GetName())
	require.Equal(t, "app", att.Subject[1].GetName())
}

func TestImportNoResolverNoDigestStrictErrors(t *testing.T) {
	// OCI purl without an embedded digest and no resolver configured:
	// NewWithError must surface errNoResolver.
	doc := vexWithProducts(vex.Product{
		Component: vex.Component{ID: "pkg:oci/app"},
	})

	att, err := NewWithError(WithPredicate(&doc))
	require.ErrorIs(t, err, errNoResolver)
	require.NotNil(t, att)
}

func TestImportNoResolverNoDigestBestEffortSkips(t *testing.T) {
	// Best-effort New must skip the unresolvable product rather than error.
	doc := vexWithProducts(
		vex.Product{Component: vex.Component{ID: "pkg:oci/app"}},
		vex.Product{Component: vex.Component{ID: "pkg:oci/good@sha256:abc"}},
	)

	att := New(WithPredicate(&doc))
	require.Len(t, att.Subject, 1, "unresolvable purl is skipped; the one with an embedded digest is kept")
	require.Equal(t, "good@sha256:abc", att.Subject[0].GetName())
}
