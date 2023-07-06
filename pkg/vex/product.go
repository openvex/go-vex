/*
Copyright 2023 The OpenVEX Authors
SPDX-License-Identifier: Apache-2.0
*/

package vex

// Component abstracts the common construct shared by product and subcomponents
// allowing OpenVEX statements to point to a piece of software by identifier,
// hash or identifier.
//
// The ID should be an IRI uniquely identifying the product. Software can be
// referenced as a VEX product or subcomponent using only its IRI or it may be
// referenced by its crptographic hashes and/or other identifiers but, in no case,
// must an IRI describe two different pieces of software or used to describe
// a range of software.
type Component struct {
	ID          string                    `json:"@id,omitempty"`
	Hashes      map[Algorithm]Hash        `json:"hashes,omitempty"`
	Identifiers map[IdentifierType]string `json:"identifiers,omitempty"`
}

// Product abstracts the VEX product into a struct that can identify sofware
// through various means. The main one is the ID field which contains an IRI
// identifying the product, possibly pointing to another document with more data,
// like an SBOM. The Product struct also supports naming software using its
// identifiers and/or cryptographic hashes.
type Product struct {
	Component
	Subcomponents []Subcomponent `json:"subcomponents,omitempty"`
}

// Subcomponents are nested entries that list the product's components that are
// related to the statement's vulnerability. The main difference with Product
// and Subcomponent objects is that a Subcomponent cannot nest components.
type Subcomponent struct {
	Component
}

type Algorithm string
type Hash string

type IdentifierType string
type IdentifierLocator string
