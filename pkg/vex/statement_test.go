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
