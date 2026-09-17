// Copyright 2026 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// canonicalHashFixture returns a document exercising every field that feeds
// CanonicalHash: doc metadata, statement timestamps (present and inherited),
// vulnerability aliases, multiple products with hashes, identifiers and
// subcomponents. Components carry at most one hash and one identifier so the
// result does not depend on map iteration order.
func canonicalHashFixture(n int) *VEX {
	docTS := time.Date(2024, 3, 1, 12, 0, 0, 0, time.UTC)
	doc := &VEX{
		Metadata: Metadata{
			Author:    "Test Author",
			Version:   3,
			Timestamp: &docTS,
		},
	}
	for i := range n {
		s := Statement{
			Vulnerability: Vulnerability{
				ID:      fmt.Sprintf("https://example.com/vulns/%d", i),
				Name:    VulnerabilityID(fmt.Sprintf("CVE-2024-%05d", i)),
				Aliases: []VulnerabilityID{"GHSA-zzzz", "GHSA-aaaa"},
			},
			Status:        StatusNotAffected,
			Justification: ComponentNotPresent,
			Products: []Product{
				{
					Component: Component{
						ID:          "pkg:oci/zeta@sha256:beef",
						Hashes:      map[Algorithm]Hash{SHA256: "beef"},
						Identifiers: map[IdentifierType]string{PURL: "pkg:oci/zeta@sha256:beef"},
					},
					Subcomponents: []Subcomponent{
						{Component: Component{ID: "pkg:apk/wolfi/libz@1.3"}},
						{Component: Component{ID: "pkg:apk/wolfi/liba@1.0"}},
					},
				},
				{Component: Component{ID: "pkg:oci/alpha@sha256:cafe"}},
			},
		}
		// Give every other statement its own timestamp; the rest inherit
		// the document's.
		if i%2 == 0 {
			ts := docTS.Add(time.Duration(i) * time.Hour)
			s.Timestamp = &ts
		}
		doc.Statements = append(doc.Statements, s)
	}
	return doc
}

func TestCanonicalHashFixture(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		n    int
		want string
	}{
		{"empty", 0, "2ceca891f56cc74b5c8b10e59d0cb0eec2863c14bd6d3dc1e8d5257c8892a44c"},
		{"one", 1, "3271817c8ce125c34c506753e45306ed56ab6e154c1bff47f13eae6d5e4407e5"},
		{"many", 7, "395f0269c1586deefc920f0dc876cd0690dc3bbd50854bf2c76dfb2e6638c607"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			doc := canonicalHashFixture(tc.n)
			got, err := doc.CanonicalHash()
			require.NoError(t, err)
			require.Equal(t, tc.want, got)

			// Hashing again must be stable.
			again, err := doc.CanonicalHash()
			require.NoError(t, err)
			require.Equal(t, got, again)
		})
	}

	t.Run("no timestamp", func(t *testing.T) {
		t.Parallel()
		doc := canonicalHashFixture(1)
		doc.Timestamp = nil
		_, err := doc.CanonicalHash()
		require.Error(t, err)
	})

	t.Run("metadata changes alter hash", func(t *testing.T) {
		t.Parallel()
		base, err := canonicalHashFixture(2).CanonicalHash()
		require.NoError(t, err)

		doc := canonicalHashFixture(2)
		doc.Version++
		got, err := doc.CanonicalHash()
		require.NoError(t, err)
		require.NotEqual(t, base, got)

		doc = canonicalHashFixture(2)
		doc.Statements[0].Status = StatusAffected
		got, err = doc.CanonicalHash()
		require.NoError(t, err)
		require.NotEqual(t, base, got)
	})
}

func BenchmarkCanonicalHash(b *testing.B) {
	for _, n := range []int{100, 1000, 5000} {
		doc := canonicalHashFixture(n)
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := doc.CanonicalHash(); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
