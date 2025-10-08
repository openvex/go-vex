// Copyright 2025 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/vex"
)

func statementList(t *testing.T) []*vex.Statement {
	t.Helper()
	return []*vex.Statement{
		{
			Vulnerability: vex.Vulnerability{
				Name: "CVE-1234-56789",
				Aliases: []vex.VulnerabilityID{
					"GHE-1234-56789",
				},
			},
			Products: []vex.Product{
				{
					Component: vex.Component{
						Hashes: map[vex.Algorithm]vex.Hash{
							vex.SHA256: "cdd80609c252ba5336de7033518cfe15f9e466a53c1de14545cc6ec22e56252b",
							vex.SHA512: "382d6447ce20980b363fb0e6e7b7e9a4544dac3bc7c8ee5e5cf78f4d5982ddfaf02dc287b58693de44d1117851219bb435dc4bc2c6a9b0a75779a2fbc84f5e6f",
						},
					},
					Subcomponents: []vex.Subcomponent{
						{
							Component: vex.Component{
								Identifiers: map[vex.IdentifierType]string{
									vex.PURL: "golang:github.com/my/package@1.2",
								},
							},
						},
						{
							Component: vex.Component{
								Identifiers: map[vex.IdentifierType]string{
									vex.PURL: "golang:github.com/my/other/package@2.0",
								},
							},
						},
					},
				},
			},
		},
		{
			Vulnerability: vex.Vulnerability{
				Name: "CVE-9876-54321",
				Aliases: []vex.VulnerabilityID{
					"GHE-9876-54321",
				},
			},
			Products: []vex.Product{
				{
					Component: vex.Component{
						Hashes: map[vex.Algorithm]vex.Hash{
							vex.SHA256: "eb69e4dc450281ac1ac675e45cff08c8452241d4664b713ea9859902272536fa",
						},
						Identifiers: map[vex.IdentifierType]string{
							vex.PURL: "oci:alpine@eb69e4dc450281ac1ac675e45cff08c8452241d4664b713ea9859902272536fa",
						},
					},
				},
				{
					Component: vex.Component{
						Hashes: map[vex.Algorithm]vex.Hash{
							vex.SHA1: "f77d09006b5a5977faaedf8857cdace0247901ba",
						},
					},
					Subcomponents: []vex.Subcomponent{
						{
							Component: vex.Component{
								Identifiers: map[vex.IdentifierType]string{
									vex.PURL: "npm:chido@1.2",
								},
							},
						},
						{
							Component: vex.Component{
								Identifiers: map[vex.IdentifierType]string{
									vex.PURL: "npm:otrchido@2.0",
								},
							},
						},
					},
				},
			},
		},
	}
}

func TestMatch(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name           string
		filters        []FilterFunc
		expectedLength int
	}{
		{name: "test", filters: []FilterFunc{}, expectedLength: 0},
		{name: "vuln", filters: []FilterFunc{WithVulnerability(&vex.Vulnerability{Name: "CVE-1234-56789"})}, expectedLength: 1},
		{name: "vulnAlias", filters: []FilterFunc{WithVulnerability(&vex.Vulnerability{Name: "CVE-1234-56789", Aliases: []vex.VulnerabilityID{"GHE-1234-56789"}})}, expectedLength: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			list := statementList(t)
			si := &StatementIndex{}
			si.IndexStatements(list)

			// Match and apply the filters
			res := si.Matches(tc.filters...)
			require.Len(t, res, tc.expectedLength)
		})
	}
}

func TestIndexStatements(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
	}{
		{name: "test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			list := statementList(t)
			si := &StatementIndex{}
			si.IndexStatements(list)

			require.Len(t, si.prodIndex, 12)
			require.Len(t, si.vulnIndex, 4)
			require.Len(t, si.subIndex, 4)
		})
	}
}
