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
				Component: Component{ID: testLibcryptoPURL},
			},
			product:      testLibcryptoPURL,
			subcomponent: "",
			mustMach:     true,
		},
		"purl only": {
			sut: &Product{
				Component: Component{Identifiers: map[IdentifierType]string{
					PURL: testLibcryptoPURL,
				}},
			},
			product:      testLibcryptoPURL,
			subcomponent: "",
			mustMach:     true,
		},
		"generic purl only": {
			sut: &Product{
				Component: Component{Identifiers: map[IdentifierType]string{
					PURL: "pkg:apk/alpine/libcrypto3",
				}},
			},
			product:      testLibcryptoPURL,
			subcomponent: "",
			mustMach:     true,
		},
		"identifier and components in doc and statement": {
			sut: &Product{
				Component: Component{ID: testAlpineOCIPURL},
				Subcomponents: []Subcomponent{
					{
						Component{ID: testLibcryptoPURL},
					},
				},
			},
			product:      testAlpineOCIPURL,
			subcomponent: testLibcryptoPURL,
			mustMach:     true,
		},
		"identifier and no components in query": {
			sut: &Product{
				Component: Component{ID: testAlpineOCIPURL},
				Subcomponents: []Subcomponent{
					{
						Component{ID: testLibcryptoPURL},
					},
				},
			},
			product:      testAlpineOCIPURL,
			subcomponent: "",
			mustMach:     true,
		},
		"identifier and no components in document": {
			sut: &Product{
				Component:     Component{ID: testAlpineOCIPURL},
				Subcomponents: []Subcomponent{},
			},
			product:      testAlpineOCIPURL,
			subcomponent: testLibcryptoPURL,
			mustMach:     true,
		},
		"identifier + multicomponent doc": {
			sut: &Product{
				Component: Component{ID: testAlpineOCIPURL},
				Subcomponents: []Subcomponent{
					{Component{ID: testLibcryptoPURL}},
					{Component{ID: "pkg:apk/alpine/libssl@3.0.8-r3"}},
				},
			},
			product:      testAlpineOCIPURL,
			subcomponent: "pkg:apk/alpine/libssl@3.0.8-r3",
			mustMach:     true,
		},
	} {
		require.Equal(t, tc.mustMach, tc.sut.Matches(tc.product, tc.subcomponent), "failed: %s", testCase)
	}
}
