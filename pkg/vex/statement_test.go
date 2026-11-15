// Copyright 2025 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestStatementEmptyTimeStamp(t *testing.T) {
	t.Parallel()
	n := time.Now()
	for _, tt := range []struct {
		name        string
		timestamp   *time.Time
		lastUpdated *time.Time
	}{
		{"both", &n, &n},
		{"only-timestamp", &n, nil},
		{"only-lastupdate", nil, &n},
		{"none", nil, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			data, err := json.Marshal(&Statement{
				Timestamp:   tt.timestamp,
				LastUpdated: tt.lastUpdated,
			})
			require.NoError(t, err)
			jsondata := string(data)

			// Unmarshal the statement to check for values
			smap := map[string]any{}
			err = json.Unmarshal(data, &smap)
			require.NoError(t, err)
			tsval, tsexists := smap["timestamp"]
			luval, luexists := smap["last_updated"]

			if tt.timestamp == nil {
				require.NotContains(t, jsondata, `"timestamp"`)
				require.False(t, tsexists)
			} else {
				require.Contains(t, jsondata, `"timestamp"`)
				require.True(t, tsexists)
				require.NotEmpty(t, tsval)
			}

			if tt.lastUpdated == nil {
				require.NotContains(t, jsondata, `"last_updated"`)
				require.False(t, luexists)
			} else {
				require.Contains(t, jsondata, `"last_updated"`)
				require.True(t, luexists)
				require.NotEmpty(t, luval)
			}
		})
	}
}

func statementAliasFixture() Document {
	ts := time.Date(2023, 1, 2, 3, 4, 5, 0, time.UTC)
	doc := New()
	doc.Statements = []Statement{
		{
			Vulnerability: Vulnerability{
				Name:    "CVE-2014-123456",
				Aliases: []VulnerabilityID{"GHSA-1234-5678-9012"},
			},
			Timestamp: &ts,
			Products: []Product{
				{Component: Component{ID: "pkg:apk/wolfi/bash@1.0"}},
			},
			Status:        StatusNotAffected,
			Justification: ComponentNotPresent,
		},
	}
	return doc
}

func TestExtractStatementsDoesNotAliasDocumentData(t *testing.T) {
	t.Parallel()

	t.Run("timestamp", func(t *testing.T) {
		t.Parallel()
		doc := statementAliasFixture()
		extracted := doc.ExtractStatements()
		require.Len(t, extracted, 1)
		require.NotSame(t, doc.Statements[0].Timestamp, extracted[0].Timestamp,
			"extracted statement shares the document statement timestamp pointer")
	})

	t.Run("products", func(t *testing.T) {
		t.Parallel()
		doc := statementAliasFixture()
		extracted := doc.ExtractStatements()
		require.Len(t, extracted, 1)
		extracted[0].Products[0].ID = "pkg:apk/wolfi/mutated@1.0"
		require.Equal(t, "pkg:apk/wolfi/bash@1.0", doc.Statements[0].Products[0].ID,
			"writing to the extracted product list modified the document")
	})

	t.Run("aliases", func(t *testing.T) {
		t.Parallel()
		doc := statementAliasFixture()
		extracted := doc.ExtractStatements()
		require.Len(t, extracted, 1)
		extracted[0].Vulnerability.Aliases[0] = "GHSA-0000-0000-0000"
		require.Equal(t, VulnerabilityID("GHSA-1234-5678-9012"), doc.Statements[0].Vulnerability.Aliases[0],
			"writing to the extracted alias list modified the document")
	})
}
