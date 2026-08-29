/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package vex

import "github.com/openvex/go-vex/pkg/csaf"

// Status describes the exploitability status of a component with respect to a
// vulnerability.
type Status string

const (
	// StatusNotAffected means no remediation or mitigation is required.
	StatusNotAffected Status = "not_affected"

	// StatusAffected means actions are recommended to remediate or mitigate.
	StatusAffected Status = "affected"

	// StatusFixed means the listed products or components have been remediated (by including fixes).
	StatusFixed Status = "fixed"

	// StatusUnderInvestigation means the author of the VEX statement is investigating.
	StatusUnderInvestigation Status = "under_investigation"
)

// Statuses returns a list of the valid Status values.
func Statuses() []string {
	return []string{
		string(StatusNotAffected),
		string(StatusAffected),
		string(StatusFixed),
		string(StatusUnderInvestigation),
	}
}

// Valid returns a bool indicating whether the Status value is equal to one of the enumerated allowed values for Status.
func (s Status) Valid() bool {
	switch s {
	case StatusNotAffected,
		StatusAffected,
		StatusFixed,
		StatusUnderInvestigation:

		return true

	default:

		return false
	}
}

// StatusFromCSAF returns a vex status from the CSAF status
func StatusFromCSAF(csafStatus string) Status {
	switch csaf.ProductStatusName(csafStatus) {
	case csaf.ProductStatusKnownNotAffected:
		return StatusNotAffected
	case csaf.ProductStatusFixed,
		csaf.ProductStatusFirstFixed,
		csaf.ProductStatusRecommended:
		return StatusFixed
	case csaf.ProductStatusUnderInvestigation:
		return StatusUnderInvestigation
	case csaf.ProductStatusKnownAffected,
		csaf.ProductStatusFirstAffected,
		csaf.ProductStatusLastAffected:
		return StatusAffected
	default:
		return ""
	}
}
