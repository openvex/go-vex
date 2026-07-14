// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package csaf

import (
	"fmt"
	"strings"
)

// ProductStatusName identifies one of the CSAF product_status buckets.
type ProductStatusName string

const (
	ProductStatusFirstAffected      = "first_affected"
	ProductStatusFirstFixed         = "first_fixed"
	ProductStatusFixed              = "fixed"
	ProductStatusKnownAffected      = "known_affected"
	ProductStatusKnownNotAffected   = "known_not_affected"
	ProductStatusLastAffected       = "last_affected"
	ProductStatusRecommended        = "recommended"
	ProductStatusUnderInvestigation = "under_investigation"
)

// ProductStatus contains CSAF product status buckets keyed by status name.
type ProductStatus map[string][]string

// ProductStatusNames returns the CSAF product status names defined by the
// schema in a stable order.
func ProductStatusNames() []string {
	return []string{
		string(ProductStatusFirstAffected),
		string(ProductStatusFirstFixed),
		string(ProductStatusFixed),
		string(ProductStatusKnownAffected),
		string(ProductStatusKnownNotAffected),
		string(ProductStatusLastAffected),
		string(ProductStatusRecommended),
		string(ProductStatusUnderInvestigation),
	}
}

// Valid reports whether the product status name is defined by CSAF.
func (status ProductStatusName) Valid() bool {
	switch status {
	case ProductStatusFirstAffected,
		ProductStatusFirstFixed,
		ProductStatusFixed,
		ProductStatusKnownAffected,
		ProductStatusKnownNotAffected,
		ProductStatusLastAffected,
		ProductStatusRecommended,
		ProductStatusUnderInvestigation:
		return true
	default:
		return false
	}
}

// Affected reports whether the CSAF status denotes an affected product.
func (status ProductStatusName) Affected() bool {
	switch status {
	case ProductStatusFirstAffected,
		ProductStatusKnownAffected,
		ProductStatusLastAffected:
		return true
	default:
		return false
	}
}

// Fixed reports whether the CSAF status denotes a fixed product.
func (status ProductStatusName) Fixed() bool {
	switch status {
	case ProductStatusFirstFixed,
		ProductStatusFixed,
		ProductStatusRecommended:
		return true
	default:
		return false
	}
}

// Validate verifies that the product status only uses CSAF-defined status names.
func (ps ProductStatus) Validate() error {
	for status := range ps {
		if !ProductStatusName(status).Valid() {
			return fmt.Errorf("invalid product_status value %q, must be one of [%s]", status, strings.Join(ProductStatusNames(), ", "))
		}
	}
	return nil
}
