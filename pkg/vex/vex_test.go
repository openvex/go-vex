/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package vex

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestLoadYAML(t *testing.T) {
	vexDoc, err := OpenYAML("testdata/vex.yaml")
	require.NoError(t, err)

	require.Len(t, vexDoc.Statements, 2)
}

func TestLoadCSAF(t *testing.T) {
	vexDoc, err := OpenCSAF("testdata/csaf.json", []string{})
	require.NoError(t, err)
	require.Len(t, vexDoc.Statements, 1)
	require.Len(t, vexDoc.Statements[0].Products, 1)
	require.Equal(t, vexDoc.Statements[0].Vulnerability, "CVE-2009-4487")
	require.Equal(t, vexDoc.Statements[0].Status, StatusNotAffected)
	require.Equal(t, vexDoc.Metadata.ID, "2022-EVD-UC-01-NA-001")
}

func TestEffectiveStatement(t *testing.T) {
	date1 := time.Date(2023, 4, 17, 20, 34, 58, 0, time.UTC)
	date2 := time.Date(2023, 4, 18, 20, 34, 58, 0, time.UTC)
	for _, tc := range []struct {
		vexDoc         *VEX
		vulnID         string
		product        string
		shouldNil      bool
		expectedDate   *time.Time
		expectedStatus Status
	}{
		{
			// Single statement
			vexDoc: &VEX{
				Statements: []Statement{
					{
						Vulnerability: "CVE-2014-123456",
						Timestamp:     &date1,
						Products:      []string{"pkg://deb@1.0"},
						Status:        StatusNotAffected,
					},
				},
			},
			vulnID:         "CVE-2014-123456",
			product:        "pkg://deb@1.0",
			shouldNil:      false,
			expectedDate:   &date1,
			expectedStatus: StatusNotAffected,
		},
		{
			// Two consecutive statemente
			vexDoc: &VEX{
				Statements: []Statement{
					{
						Vulnerability: "CVE-2014-123456",
						Timestamp:     &date1,
						Products:      []string{"pkg://deb@1.0"},
						Status:        StatusUnderInvestigation,
					},
					{
						Vulnerability: "CVE-2014-123456",
						Timestamp:     &date2,
						Products:      []string{"pkg://deb@1.0"},
						Status:        StatusNotAffected,
					},
				},
			},
			vulnID:         "CVE-2014-123456",
			product:        "pkg://deb@1.0",
			shouldNil:      false,
			expectedDate:   &date2,
			expectedStatus: StatusNotAffected,
		},
		{
			// Different products
			vexDoc: &VEX{
				Statements: []Statement{
					{
						Vulnerability: "CVE-2014-123456",
						Timestamp:     &date1,
						Products:      []string{"pkg://deb@1.0"},
						Status:        StatusUnderInvestigation,
					},
					{
						Vulnerability: "CVE-2014-123456",
						Timestamp:     &date2,
						Products:      []string{"pkg://deb@2.0"},
						Status:        StatusNotAffected,
					},
				},
			},
			vulnID:         "CVE-2014-123456",
			product:        "pkg://deb@1.0",
			shouldNil:      false,
			expectedDate:   &date1,
			expectedStatus: StatusUnderInvestigation,
		},
	} {
		s := tc.vexDoc.EffectiveStatement(tc.product, tc.vulnID)
		if tc.shouldNil {
			require.Nil(t, s)
		} else {
			require.Equal(t, tc.expectedDate, s.Timestamp)
			require.Equal(t, tc.expectedStatus, s.Status)
		}
	}
}

func genTestDoc(t *testing.T) VEX {
	ts, err := time.Parse(time.RFC3339, "2022-12-22T16:36:43-05:00")
	require.NoError(t, err)
	return VEX{
		Metadata: Metadata{
			Author:     "John Doe",
			AuthorRole: "VEX Writer Extraordinaire",
			Timestamp:  &ts,
			Version:    "1",
			Tooling:    "OpenVEX",
			Supplier:   "Chainguard Inc",
		},
		Statements: []Statement{
			{
				Vulnerability:   "CVE-1234-5678",
				VulnDescription: "",
				Products: []Product{
					{
						Component: Component{
							ID: "pkg:oci/example@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
						},
						Subcomponents: []Subcomponent{
							{
								Component: Component{
									ID: "pkg:apk/wolfi/bash@1.0.0",
								},
							},
						},
					},
				},
				Status: "under_investigation",
			},
		},
	}
}

func TestCanonicalHash(t *testing.T) {
	goldenHash := `3397119e99cb71129dada8fbc96722eb59121839cf9018dc327e0215bc7843bf`

	otherTS, err := time.Parse(time.RFC3339, "2019-01-22T16:36:43-05:00")
	require.NoError(t, err)

	for i, tc := range []struct {
		prepare   func(*VEX)
		expected  string
		shouldErr bool
	}{
		// Default Expected
		{func(v *VEX) {}, goldenHash, false},
		// Adding a statement changes the hash
		{
			func(v *VEX) {
				v.Statements = append(v.Statements, Statement{
					Vulnerability: "CVE-2010-543231",
					Products: []Product{
						{Component: Component{ID: "pkg:apk/wolfi/git@2.0.0"}},
					},
					Status: "affected",
				})
			},
			"0ba39edb13118b7396c0d1ee13d0d38d4a3303381e22e86a1b2c9d723793a832",
			false,
		},
		// Changing metadata should not change hash
		{
			func(v *VEX) {
				v.AuthorRole = "abc"
				v.ID = "298347" // Mmhh...
				v.Supplier = "Mr Supplier"
				v.Tooling = "Fake Tool 1.0"
			},
			goldenHash,
			false,
		},
		// Changing other statement metadata should not change the hash
		{
			func(v *VEX) {
				v.Statements[0].ActionStatement = "Action!"
				v.Statements[0].VulnDescription = "It is very bad"
				v.Statements[0].StatusNotes = "Let's note somthn here"
				v.Statements[0].ImpactStatement = "We evaded this CVE by a hair"
				v.Statements[0].ActionStatementTimestamp = &otherTS
			},
			goldenHash,
			false,
		},
		// Changing products changes the hash
		{
			func(v *VEX) {
				v.Statements[0].Products[0].ID = "cool router, bro"
			},
			"d042a7f2bbf3bd2c59b744cfe310ec11c920f99344eaa95fad115c323217ec33",
			false,
		},
		// Changing document time changes the hash
		{
			func(v *VEX) {
				v.Timestamp = &otherTS
			},
			"aba93636cf64a52949d82b7862f76dd9bd361097e1bbe6881fbac495b933c774",
			false,
		},
		// Same timestamp in statement as doc should not change the hash
		{
			func(v *VEX) {
				v.Statements[0].Timestamp = v.Timestamp
			},
			goldenHash,
			false,
		},
	} {
		doc := genTestDoc(t)
		tc.prepare(&doc)
		hashString, err := doc.CanonicalHash()
		if tc.shouldErr {
			require.Error(t, err)
		} else {
			require.NoError(t, err)
		}
		require.Equal(t, tc.expected, hashString, fmt.Sprintf("Testcase #%d %s", i, doc.Statements[0].Products[0]))
	}
}

func TestGenerateCanonicalID(t *testing.T) {
	for _, tc := range []struct {
		prepare    func(*VEX)
		expectedID string
	}{
		{
			// Normal generation
			prepare:    func(v *VEX) {},
			expectedID: "https://openvex.dev/docs/public/vex-3397119e99cb71129dada8fbc96722eb59121839cf9018dc327e0215bc7843bf",
		},
		{
			// Existing IDs should not be changed
			prepare:    func(v *VEX) { v.ID = "VEX-ID-THAT-ALREADY-EXISTED" },
			expectedID: "VEX-ID-THAT-ALREADY-EXISTED",
		},
	} {
		doc := genTestDoc(t)
		tc.prepare(&doc)
		id, err := doc.GenerateCanonicalID()
		require.NoError(t, err)
		require.Equal(t, tc.expectedID, id)
	}
}

func TestOpenCSAF(t *testing.T) {
	for _, tc := range []struct {
		doc string
		len int
		id  []string
	}{
		{"testdata/csaf.json", 1, []string{"CSAFPID-0001"}},
		{"testdata/csaf.json", 1, []string{"pkg:golang/github.com/go-homedir@v1.2.0"}},
	} {
		doc, err := OpenCSAF(tc.doc, tc.id)
		require.NoError(t, err)
		require.NotNil(t, doc)
		require.Len(t, doc.Statements, tc.len)
	}
}
