// Copyright 2025 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package index

import (
	"fmt"
	"slices"

	"github.com/openvex/go-vex/pkg/vex"
)

// New creates a new VEX index with the specified functions
func New(funcs ...constructorFunc) (*StatementIndex, error) {
	si := &StatementIndex{}
	for _, fn := range funcs {
		if err := fn(si); err != nil {
			return nil, err
		}
	}
	return si, nil
}

type constructorFunc func(*StatementIndex) error

// WithDocument adds all the statements in a document to the index
func WithDocument(doc *vex.VEX) constructorFunc {
	return func(si *StatementIndex) error {
		statements := []*vex.Statement{}
		for i := range doc.Statements {
			statements = append(statements, &doc.Statements[i])
		}
		si.IndexStatements(statements)
		return nil
	}
}

// WithStatements adds statements to a newly created index
func WithStatements(statements []*vex.Statement) constructorFunc {
	return func(si *StatementIndex) error {
		si.IndexStatements(statements)
		return nil
	}
}

// StatementIndex is the OpenVEX statement indexer. An index reads into memory
// vex statements and catalogs them by the fields in their components
// (vulnerability, product, subcomponents).
//
// The index exposes a StatementIndex.Match() function that takes in Filters
// to return indexed statements that match the filter criteria.
type StatementIndex struct {
	vulnIndex map[string][]*vex.Statement
	prodIndex map[string][]*vex.Statement
	subIndex  map[string][]*vex.Statement
}

// IndexStatements indexes all the passed statements by cataloguing the
// fields in the product, vulnerability and subcomponents.
func (si *StatementIndex) IndexStatements(statements []*vex.Statement) {
	si.vulnIndex = map[string][]*vex.Statement{}
	si.prodIndex = map[string][]*vex.Statement{}
	si.subIndex = map[string][]*vex.Statement{}

	for _, s := range statements {
		for _, p := range s.Products {
			if p.ID != "" {
				si.prodIndex[p.ID] = append(si.prodIndex[p.ID], s)
			}
			for _, id := range p.Identifiers {
				if !slices.Contains(si.prodIndex[id], s) {
					si.prodIndex[id] = append(si.prodIndex[id], s)
				}
			}
			for algo, h := range p.Hashes {
				if !slices.Contains(si.prodIndex[string(h)], s) {
					si.prodIndex[string(h)] = append(si.prodIndex[string(h)], s)
				}
				if !slices.Contains(si.prodIndex[fmt.Sprintf("%s:%s", algo, h)], s) {
					si.prodIndex[fmt.Sprintf("%s:%s", algo, h)] = append(si.prodIndex[fmt.Sprintf("%s:%s", algo, h)], s)
				}
				intotoAlgo := algo.ToInToto()
				if intotoAlgo == "" {
					continue
				}
				if !slices.Contains(si.prodIndex[fmt.Sprintf("%s:%s", intotoAlgo, h)], s) {
					si.prodIndex[fmt.Sprintf("%s:%s", intotoAlgo, h)] = append(si.prodIndex[fmt.Sprintf("%s:%s", intotoAlgo, h)], s)
				}
			}

			// Index the subcomponents
			for _, sc := range p.Subcomponents {
				// Match by ID too
				if sc.ID != "" && !slices.Contains(si.subIndex[sc.ID], s) {
					si.subIndex[sc.ID] = append(si.subIndex[sc.ID], s)
				}
				for _, id := range sc.Identifiers {
					if !slices.Contains(si.subIndex[id], s) {
						si.subIndex[id] = append(si.subIndex[id], s)
					}
				}
				for _, h := range sc.Hashes {
					if !slices.Contains(si.subIndex[string(h)], s) {
						si.subIndex[string(h)] = append(si.subIndex[string(h)], s)
					}
				}
			}
		}

		if s.Vulnerability.Name != "" {
			if !slices.Contains(si.vulnIndex[string(s.Vulnerability.Name)], s) {
				si.vulnIndex[string(s.Vulnerability.Name)] = append(si.vulnIndex[string(s.Vulnerability.Name)], s)
			}
		}
		for _, alias := range s.Vulnerability.Aliases {
			if !slices.Contains(si.vulnIndex[string(alias)], s) {
				si.vulnIndex[string(alias)] = append(si.vulnIndex[string(alias)], s)
			}
		}
	}
}

// unionIndexResults
func unionIndexResults(results []map[*vex.Statement]struct{}) []*vex.Statement {
	if len(results) == 0 {
		return []*vex.Statement{}
	}
	preret := map[*vex.Statement]struct{}{}
	// Since we're looking for statements in all results, we can just
	// cycle the shortest list against the others
	slices.SortFunc(results, func(a, b map[*vex.Statement]struct{}) int {
		if len(a) == len(b) {
			return 0
		}
		if len(a) < len(b) {
			return -1
		}
		return 1
	})

	var found bool
	for s := range results[0] {
		// if this is present in all lists, we're in
		found = true
		for i := range results[1:] {
			if _, ok := results[i][s]; !ok {
				found = false
				break
			}
		}
		if found {
			preret[s] = struct{}{}
		}
	}

	// Now assemble the list
	ret := []*vex.Statement{}
	for s := range preret {
		ret = append(ret, s)
	}
	return ret
}

// Matches applies filters to the index to look for matching statements
func (si *StatementIndex) Matches(filterfunc ...FilterFunc) []*vex.Statement {
	lists := []map[*vex.Statement]struct{}{}
	for _, ffunc := range filterfunc {
		filter := ffunc(si)
		lists = append(lists, filter())
	}
	return unionIndexResults(lists)
}
