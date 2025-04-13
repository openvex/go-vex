// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProductMatches(t *testing.T) {
	for testCase, tc := range map[string]struct {
		sut          *Product
		product      string
		subcomponent string
		mustMach     bool
	}{
		"identifier only": {
			sut: &Product{
				Component: Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"},
			},
			product:      "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			subcomponent: "",
			mustMach:     true,
		},
		"purl only": {
			sut: &Product{
				Component: Component{Identifiers: map[IdentifierType]string{
					PURL: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
				}},
			},
			product:      "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			subcomponent: "",
			mustMach:     true,
		},
		"generic purl only": {
			sut: &Product{
				Component: Component{Identifiers: map[IdentifierType]string{
					PURL: "pkg:apk/alpine/libcrypto3",
				}},
			},
			product:      "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			subcomponent: "",
			mustMach:     true,
		},
		"identifier and components in doc and statement": {
			sut: &Product{
				Component: Component{ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"},
				Subcomponents: []Subcomponent{
					{
						Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"},
					},
				},
			},
			product:      "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			subcomponent: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			mustMach:     true,
		},
		"identifier and no components in query": {
			sut: &Product{
				Component: Component{ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"},
				Subcomponents: []Subcomponent{
					{
						Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"},
					},
				},
			},
			product:      "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			subcomponent: "",
			mustMach:     true,
		},
		"identifier and no components in document": {
			sut: &Product{
				Component:     Component{ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"},
				Subcomponents: []Subcomponent{},
			},
			product:      "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			subcomponent: "pkg:apk/alpine/libcrypto3@3.0.8-r3",
			mustMach:     true,
		},
		"identifier + multicomponent doc": {
			sut: &Product{
				Component: Component{ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126"},
				Subcomponents: []Subcomponent{
					{Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"}},
					{Component{ID: "pkg:apk/alpine/libssl@3.0.8-r3"}},
				},
			},
			product:      "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			subcomponent: "pkg:apk/alpine/libssl@3.0.8-r3",
			mustMach:     true,
		},
	} {
		require.Equal(t, tc.mustMach, tc.sut.Matches(tc.product, tc.subcomponent), "failed: %s", testCase)
	}
}
