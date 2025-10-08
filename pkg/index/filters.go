// Copyright 2025 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package index

import "github.com/openvex/go-vex/pkg/vex"

// Filter is an internal object that abstracs a function that
// when called, extracts vex statements from an index, returning them
// in a slice ordered by pointers so the matching vex statements.
//
// Filters are used by the index `Matches()` function which calls the
// filters, deduplicates the results and returns the collection of matching
// statements.
type Filter func() map[*vex.Statement]struct{}

// A FilterFunc is a function that returns a Filter when called. FilterFuncs are
// meant to be used as arguments to the `Matches()` index function.
type FilterFunc func(*StatementIndex) Filter

// WithVulnerability returns a filter that matches a vulnerability.
func WithVulnerability(vuln *vex.Vulnerability) FilterFunc {
	return func(si *StatementIndex) Filter {
		return func() map[*vex.Statement]struct{} {
			ret := map[*vex.Statement]struct{}{}
			ids := []vex.VulnerabilityID{}
			if vuln.Name != "" {
				ids = append(ids, vuln.Name)
			}
			ids = append(ids, vuln.Aliases...)

			for _, id := range ids {
				for _, s := range si.vulnIndex[string(id)] {
					ret[s] = struct{}{}
				}
			}
			return ret
		}
	}
}

// WithProduct returns a filter that indexes a product by its ID,
// identifiers and hashes.
func WithProduct(prod *vex.Product) FilterFunc {
	return func(si *StatementIndex) Filter {
		return func() map[*vex.Statement]struct{} {
			ret := map[*vex.Statement]struct{}{}
			ids := []string{}
			if prod.ID != "" {
				ids = append(ids, prod.ID)
			}
			for _, id := range prod.Identifiers {
				ids = append(ids, id)
			}
			for _, h := range prod.Hashes {
				ids = append(ids, string(h))
			}

			for _, id := range ids {
				for _, s := range si.prodIndex[id] {
					ret[s] = struct{}{}
				}
			}

			return ret
		}
	}
}

// WithSubcomponent adds a subcomponent filter to the search criteria, indexing
// by ID, identifiers and hashes.
func WithSubcomponent(subc *vex.Subcomponent) FilterFunc {
	return func(si *StatementIndex) Filter {
		return func() map[*vex.Statement]struct{} {
			ret := map[*vex.Statement]struct{}{}
			ids := []string{}
			if subc.ID != "" {
				ids = append(ids, subc.ID)
			}
			for _, id := range subc.Identifiers {
				ids = append(ids, id)
			}
			for _, h := range subc.Hashes {
				ids = append(ids, string(h))
			}

			for _, id := range ids {
				for _, s := range si.subIndex[id] {
					ret[s] = struct{}{}
				}
			}

			return ret
		}
	}
}
