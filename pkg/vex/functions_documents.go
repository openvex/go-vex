/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package vex

import (
	"sort"
)

// SortDocuments sorts and returns a slice of documents based on their date.
// VEXes should be applied sequentially in chronological order as they capture
// knowledge about an artifact as it changes over time.
func SortDocuments(docs []*VEX) []*VEX {
	sort.Slice(docs, func(i, j int) bool {
		if docs[j].Timestamp == nil {
			return true
		}
		if docs[i].Timestamp == nil {
			return false
		}
		return docs[i].Timestamp.Before(*(docs[j].Timestamp))
	})
	return docs
}
