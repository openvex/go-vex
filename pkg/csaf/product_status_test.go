// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package csaf

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

const testProductID1 = "CSAFPID-0001"

func TestProductStatusNames(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{
		"first_affected",
		"first_fixed",
		"fixed",
		"known_affected",
		"known_not_affected",
		"last_affected",
		"recommended",
		"under_investigation",
	}, ProductStatusNames())
}

func TestProductStatusValidate(t *testing.T) {
	t.Parallel()

	valid := ProductStatus{
		ProductStatusFirstAffected:      {testProductID1},
		ProductStatusFirstFixed:         {"CSAFPID-0002"},
		ProductStatusFixed:              {"CSAFPID-0003"},
		ProductStatusKnownAffected:      {"CSAFPID-0004"},
		ProductStatusKnownNotAffected:   {"CSAFPID-0005"},
		ProductStatusLastAffected:       {"CSAFPID-0006"},
		ProductStatusRecommended:        {"CSAFPID-0007"},
		ProductStatusUnderInvestigation: {"CSAFPID-0008"},
	}
	require.NoError(t, valid.Validate())

	invalid := ProductStatus{
		"not_a_csaf_status": {"CSAFPID-0009"},
	}
	require.ErrorContains(t, invalid.Validate(), "invalid product_status value")
}

func TestProductStatusJSON(t *testing.T) {
	t.Parallel()

	data := []byte(`{"last_affected":["CSAFPID-0001"],"first_affected":["CSAFPID-0002"]}`)
	productStatus := ProductStatus{}

	require.NoError(t, json.Unmarshal(data, &productStatus))
	require.Equal(t, []string{testProductID1}, productStatus[ProductStatusLastAffected])
	require.Equal(t, []string{"CSAFPID-0002"}, productStatus[ProductStatusFirstAffected])
	require.NoError(t, productStatus.Validate())
}

func TestValidateProductStatuses(t *testing.T) {
	t.Parallel()

	doc := CSAF{
		Vulnerabilities: []Vulnerability{
			{
				ProductStatus: ProductStatus{
					ProductStatusLastAffected: {testProductID1},
				},
			},
		},
	}
	require.NoError(t, doc.ValidateProductStatuses())

	doc.Vulnerabilities[0].ProductStatus = ProductStatus{
		"not_a_csaf_status": {testProductID1},
	}
	require.ErrorContains(t, doc.ValidateProductStatuses(), "vulnerabilities[0].product_status")
}
