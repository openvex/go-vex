// Copyright 2026 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package vex

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDeprecatedSupplierJSON(t *testing.T) {
	metadata := Metadata{Author: "Document author", Supplier: "Legacy supplier"}
	document := Document{Metadata: metadata}
	for name, value := range map[string]any{
		"metadata":         metadata,
		"document":         document,
		"document pointer": &document,
	} {
		t.Run(name, func(t *testing.T) {
			data, err := json.Marshal(value)
			require.NoError(t, err)

			var fields map[string]json.RawMessage
			require.NoError(t, json.Unmarshal(data, &fields))
			require.NotContains(t, fields, "supplier")
			require.JSONEq(t, `"Document author"`, string(fields["author"]))
		})
	}
	// The Go field remains available and serialization does not mutate it.
	require.Equal(t, "Legacy supplier", document.Supplier)
}

func TestDeprecatedSupplierLegacyJSON(t *testing.T) {
	data := []byte(`{"author":"Document author","supplier":"Legacy supplier"}`)
	t.Run("metadata", func(t *testing.T) {
		var metadata Metadata
		require.NoError(t, json.Unmarshal(data, &metadata))
		require.Empty(t, metadata.Supplier)
		require.Equal(t, "Document author", metadata.Author)
	})
	t.Run("document", func(t *testing.T) {
		var document Document
		require.NoError(t, json.Unmarshal(data, &document))
		require.Empty(t, document.Supplier)
		require.Equal(t, "Document author", document.Author)
	})
}

func TestComponentSupplierJSON(t *testing.T) {
	document := New()
	document.Statements = []Statement{{Products: []Product{{
		Component: Component{ID: "product", Supplier: "Product supplier"},
		Subcomponents: []Subcomponent{{
			Component: Component{ID: "subcomponent", Supplier: "Subcomponent supplier"},
		}},
	}}}}
	data, err := json.Marshal(&document)
	require.NoError(t, err)

	var decoded Document
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Statements, 1)
	require.Len(t, decoded.Statements[0].Products, 1)
	product := decoded.Statements[0].Products[0]
	require.Equal(t, "Product supplier", product.Supplier)
	require.Len(t, product.Subcomponents, 1)
	require.Equal(t, "Subcomponent supplier", product.Subcomponents[0].Supplier)
}
