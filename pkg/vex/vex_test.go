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

func TestEffectiveStatement(t *testing.T) {
	date1 := time.Date(2023, 4, 17, 20, 34, 58, 0, time.UTC)
	date2 := time.Date(2023, 4, 18, 20, 34, 58, 0, time.UTC)
	for caseName, tc := range map[string]struct {
		vexDoc         *VEX
		vulnID         string
		product        string
		shouldNil      bool
		expectedDate   *time.Time
		expectedStatus Status
	}{
		"Single statement": {
			vexDoc: &VEX{
				Statements: []Statement{
					{
						Vulnerability: Vulnerability{Name: "CVE-2014-123456"},
						Timestamp:     &date1,
						Products:      []Product{{Component: Component{ID: "pkg:deb/pkg@1.0"}}},
						Status:        StatusNotAffected,
					},
				},
			},
			vulnID:         "CVE-2014-123456",
			product:        "pkg:deb/pkg@1.0",
			shouldNil:      false,
			expectedDate:   &date1,
			expectedStatus: StatusNotAffected,
		},
		"Two consecutive statemente": {
			vexDoc: &VEX{
				Statements: []Statement{
					{
						Vulnerability: Vulnerability{Name: "CVE-2014-123456"},
						Timestamp:     &date1,
						Products:      []Product{{Component: Component{ID: "pkg:deb/pkg@1.0"}}},
						Status:        StatusUnderInvestigation,
					},
					{
						Vulnerability: Vulnerability{Name: "CVE-2014-123456"},
						Timestamp:     &date2,
						Products:      []Product{{Component: Component{ID: "pkg:deb/pkg@1.0"}}},
						Status:        StatusNotAffected,
					},
				},
			},
			vulnID:         "CVE-2014-123456",
			product:        "pkg:deb/pkg@1.0",
			shouldNil:      false,
			expectedDate:   &date2,
			expectedStatus: StatusNotAffected,
		},
		"Different products": {
			vexDoc: &VEX{
				Statements: []Statement{
					{
						Vulnerability: Vulnerability{Name: "CVE-2014-123456"},
						Timestamp:     &date1,
						Products:      []Product{{Component: Component{ID: "pkg:deb/pkg@1.0"}}},
						Status:        StatusUnderInvestigation,
					},
					{
						Vulnerability: Vulnerability{Name: "CVE-2014-123456"},
						Timestamp:     &date2,
						Products:      []Product{{Component: Component{ID: "pkg:deb/pkg@2.0"}}},
						Status:        StatusNotAffected,
					},
				},
			},
			vulnID:         "CVE-2014-123456",
			product:        "pkg:deb/pkg@1.0",
			shouldNil:      false,
			expectedDate:   &date1,
			expectedStatus: StatusUnderInvestigation,
		},
		"Vulnerability aliases": {
			vexDoc: &VEX{
				Statements: []Statement{
					{
						Vulnerability: Vulnerability{
							Name:    "CVE-2014-123456",
							Aliases: []VulnerabilityID{"ghsa-92xj-mqp7-vmcj"},
						},
						Timestamp: &date1,
						Products:  []Product{{Component: Component{ID: "pkg:deb/pkg@1.0"}}},
						Status:    StatusUnderInvestigation,
					},
					{
						Vulnerability: Vulnerability{ID: "CVE-2014-123456"},
						Timestamp:     &date2,
						Products:      []Product{{Component: Component{ID: "pkg:deb/pkg@2.0"}}},
						Status:        StatusNotAffected,
					},
				},
			},
			vulnID:         "ghsa-92xj-mqp7-vmcj",
			product:        "pkg:deb/pkg@1.0",
			shouldNil:      false,
			expectedDate:   &date1,
			expectedStatus: StatusUnderInvestigation,
		},
	} {
		s := tc.vexDoc.EffectiveStatement(tc.product, tc.vulnID)
		if tc.shouldNil {
			require.Nil(t, s)
		} else {
			require.NotNil(t, s, caseName)
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
			Version:    1,
			Tooling:    "OpenVEX",
			Supplier:   "Chainguard Inc",
		},
		Statements: []Statement{
			{
				Vulnerability: Vulnerability{
					Name: "CVE-1234-5678",
					Aliases: []VulnerabilityID{
						VulnerabilityID("some vulnerability alias"),
					},
				},
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
	//nolint:gosec // Not a credential
	goldenHash := `8ed99017785c3b43219018c7c50353c031cdaaf1c7efc146c683b0ce57123cf6`

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
					Vulnerability: Vulnerability{Name: "CVE-2010-543231"},
					Products: []Product{
						{Component: Component{ID: "pkg:apk/wolfi/git@2.0.0"}},
					},
					Status: "affected",
				})
			},
			"cbfbba00d118572164b5b934e3ced71c1b02e171f942abfe66d42775dba703cf",
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
			"010aaeb3d6bf69c486e199a48ec40038ca347d2603142dd48d97937d8477fe37",
			false,
		},
		// Changing document time changes the hash
		{
			func(v *VEX) {
				v.Timestamp = &otherTS
			},
			"d585979c1cc06797d2486382b3fd5e95d3a9b416525c95c9fefcef9863a595c8",
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
			expectedID: "https://openvex.dev/docs/public/vex-8ed99017785c3b43219018c7c50353c031cdaaf1c7efc146c683b0ce57123cf6",
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

func TestPurlMatches(t *testing.T) {
	for caseName, tc := range map[string]struct {
		p1        string
		p2        string
		mustMatch bool
	}{
		"same purl":         {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", true},
		"different type":    {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:rpm/wolfi/curl@8.1.2-r0?arch=x86_64", false},
		"different ns":      {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/alpine/curl@8.1.2-r0?arch=x86_64", false},
		"different package": {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/wolfi/bash@8.1.2-r0?arch=x86_64", false},
		"different version": {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/wolfi/bash@8.1.3-r0?arch=x86_64", false},
		"p1 no qualifiers":  {"pkg:apk/wolfi/curl@8.1.2-r0", "pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", true},
		"p2 no qualifiers":  {"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64", "pkg:apk/wolfi/curl@8.1.2-r0", false},
		"versionless": {
			"pkg:oci/curl",
			"pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c",
			true,
		},
		"different qualifier": {
			"pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c?arch=amd64&os=linux",
			"pkg:oci/curl@sha256:47fed8868b46b060efb8699dc40e981a0c785650223e03602d8c4493fc75b68c?arch=arm64&os=linux",
			false,
		},
		"p2 more qualifiers": {
			"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64",
			"pkg:apk/wolfi/curl@8.1.2-r0?arch=x86_64&os=linux",
			true,
		},
	} {
		require.Equal(t, tc.mustMatch, PurlMatches(tc.p1, tc.p2), fmt.Sprintf("failed testcase: %s", caseName))
	}
}

func TestDocumentMatches(t *testing.T) {
	now := time.Now()
	for testCase, tc := range map[string]struct {
		sut           *VEX
		product       string
		vulnerability string
		subcomponents []string
		mustMach      bool
		numMatches    int
	}{
		"regular match": {
			sut: &VEX{
				Metadata: Metadata{Timestamp: &now},
				Statements: []Statement{
					{
						Vulnerability: Vulnerability{ID: "CVE-2023-1255"},
						Products: []Product{
							{
								Component: Component{
									ID: "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
								},
								Subcomponents: []Subcomponent{
									// {Component: Component{ID: "pkg:apk/alpine/libcrypto3@3.0.8-r3"}},
								},
							},
						},
					},
				},
			},
			product:       "pkg:oci/alpine@sha256%3A124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126",
			vulnerability: "CVE-2023-1255",
			mustMach:      true,
			numMatches:    1,
		},
	} {
		matches := tc.sut.Matches(
			tc.vulnerability, tc.product, tc.subcomponents,
		)
		require.Equal(t, tc.numMatches, len(matches), fmt.Sprintf("failed: %s", testCase))
	}
}

func TestParseContext(t *testing.T) {
	for tCase, tc := range map[string]struct {
		docData   string
		expected  string
		shouldErr bool
	}{
		"Normal":        {`{"@context": "https://openvex.dev/ns"}`, "https://openvex.dev/ns", false},
		"Other JSON":    {`{"document": { "category": "csaf_vex" } }`, "", false},
		"Invalid JSON":  {`@context": "https://openvex.dev/ns`, "", true},
		"Other json-ld": {`{"@context": "https://spdx.dev/"}`, "", false},
	} {
		res, err := parseContext([]byte(tc.docData))
		if tc.shouldErr {
			require.Error(t, err, tCase)
			continue
		}
		require.NoError(t, err, tCase)
		require.Equal(t, res, tc.expected, tCase)
	}
}

func TestDeepCopyOfVex(t *testing.T) {
	vex := genTestDoc(t)

	// Make a copy of the vex document
	vexCopy := vex.DeepCopy()

	// Compare the two documents
	require.Equal(t, vex, *vexCopy)

	// Change the copy
	vexCopy.ID = "new ID"
	require.NotEqual(t, vex, *vexCopy)

	// Change the original
	originalAlias := vex.Statements[0].Vulnerability.Aliases[0]
	vex.Statements[0].Vulnerability.Aliases[0] = VulnerabilityID("new alias")
	require.NotEqual(t, vex, *vexCopy)
	require.Equal(t, originalAlias, vexCopy.Statements[0].Vulnerability.Aliases[0])

}
