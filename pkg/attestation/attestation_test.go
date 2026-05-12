// Copyright 2023 The OpenVEX Authors
// SPDX-License-Identifier: Apache-2.0

package attestation

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
	"time"

	intoto "github.com/in-toto/attestation/go/v1"
	"github.com/stretchr/testify/require"

	"github.com/openvex/go-vex/pkg/vex"
)

// newTestVEX returns a VEX document with a fixed timestamp for deterministic tests.
func newTestVEX() vex.VEX {
	ts := time.Date(2026, 1, 15, 10, 0, 0, 0, time.UTC)
	return vex.VEX{
		Metadata: vex.Metadata{
			Context:   vex.ContextLocator(),
			ID:        "https://openvex.dev/docs/test/vex-001",
			Author:    "mailto:test@example.com",
			Timestamp: &ts,
			Version:   1,
		},
		Statements: []vex.Statement{
			{
				Vulnerability: vex.Vulnerability{
					Name: "CVE-2024-1234",
				},
				Products: []vex.Product{
					{
						Component: vex.Component{
							ID: "pkg:oci/nginx@sha256:abc123",
						},
					},
				},
				Status:        vex.StatusNotAffected,
				Justification: vex.VulnerableCodeNotPresent,
				Timestamp:     &ts,
			},
		},
	}
}

func TestPredicateGetData(t *testing.T) {
	doc := newTestVEX()
	pred := NewPredicate(&doc)
	data := pred.GetData()
	require.NotNil(t, data)

	// The predicate data must be valid JSON
	var parsed map[string]json.RawMessage
	err := json.Unmarshal(data, &parsed)
	require.NoError(t, err)

	// Must contain the expected VEX fields
	for _, key := range []string{"@context", "@id", "author", "version", "timestamp", "statements"} {
		_, ok := parsed[key]
		require.True(t, ok, "predicate data missing key %q", key)
	}

	// Verify the author round-trips correctly
	var author string
	require.NoError(t, json.Unmarshal(parsed["author"], &author))
	require.Equal(t, "mailto:test@example.com", author)
}

func TestPredicateGetDataNilDoc(t *testing.T) {
	pred := NewPredicate(nil)
	data := pred.GetData()
	require.NotNil(t, data)

	// Even a default predicate should produce valid JSON
	var parsed map[string]json.RawMessage
	err := json.Unmarshal(data, &parsed)
	require.NoError(t, err)
	require.Contains(t, string(parsed["@context"]), "openvex.dev")
}

func TestPredicateGetType(t *testing.T) {
	doc := newTestVEX()
	pred := NewPredicate(&doc)
	require.Equal(t, PredicateType, pred.GetType())
}

func TestPredicateSetType(t *testing.T) {
	doc := newTestVEX()
	pred := NewPredicate(&doc)

	// Setting the matching type should succeed
	err := pred.SetType(PredicateType)
	require.NoError(t, err)

	// Setting a different type should fail
	err = pred.SetType("https://example.com/wrong")
	require.Error(t, err)
}

func TestAttestationMarshalJSON(t *testing.T) {
	doc := newTestVEX()
	att := &Attestation{
		Statement: &intoto.Statement{
			Type:          intoto.StatementTypeUri,
			PredicateType: string(PredicateType),
		},
		Predicate: NewPredicate(&doc),
	}
	require.NoError(t, att.AddSubjects([]*intoto.ResourceDescriptor{
		{
			Name:   "pkg:oci/nginx@sha256:abc123",
			Digest: map[string]string{"sha256": "abc123def456"},
		},
	}))

	data, err := json.Marshal(att)
	require.NoError(t, err)

	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &envelope))

	// Verify the in-toto envelope field names are spec-compliant
	require.Contains(t, envelope, "_type", "must use _type not type")
	require.Contains(t, envelope, "predicateType", "must use predicateType not predicate_type")
	require.Contains(t, envelope, "subject")
	require.Contains(t, envelope, "predicate")

	// _type must be the in-toto v1 URI
	var typ string
	require.NoError(t, json.Unmarshal(envelope["_type"], &typ))
	require.Equal(t, "https://in-toto.io/Statement/v1", typ)

	// predicateType must be the OpenVEX URI
	var predType string
	require.NoError(t, json.Unmarshal(envelope["predicateType"], &predType))
	require.Equal(t, string(PredicateType), predType)

	// subject must contain our entry
	var subjects []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["subject"], &subjects))
	require.Len(t, subjects, 1)

	var name string
	require.NoError(t, json.Unmarshal(subjects[0]["name"], &name))
	require.Equal(t, "pkg:oci/nginx@sha256:abc123", name)

	var digest map[string]string
	require.NoError(t, json.Unmarshal(subjects[0]["digest"], &digest))
	require.Equal(t, "abc123def456", digest["sha256"])

	// predicate must contain the VEX document
	var predicate map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["predicate"], &predicate))
	require.Contains(t, predicate, "@context")
	require.Contains(t, predicate, "statements")

	var author string
	require.NoError(t, json.Unmarshal(predicate["author"], &author))
	require.Equal(t, "mailto:test@example.com", author)
}

func TestAttestationMarshalNoProtobufFieldNames(t *testing.T) {
	att := New()
	data, err := json.Marshal(att)
	require.NoError(t, err)

	raw := string(data)
	// protobuf encoding/json would produce "type" and "predicate_type";
	// our MarshalJSON must produce "_type" and "predicateType" instead.
	require.NotContains(t, raw, `"type"`)
	require.NotContains(t, raw, `"predicate_type"`)
	require.Contains(t, raw, `"_type"`)
	require.Contains(t, raw, `"predicateType"`)
}

func TestAttestationToJSON(t *testing.T) {
	doc := newTestVEX()
	att := &Attestation{
		Statement: &intoto.Statement{
			Type:          intoto.StatementTypeUri,
			PredicateType: string(PredicateType),
		},
		Predicate: NewPredicate(&doc),
	}
	require.NoError(t, att.AddSubjects([]*intoto.ResourceDescriptor{
		{
			Name:   "pkg:oci/nginx@sha256:abc123",
			Digest: map[string]string{"sha256": "abc123def456"},
		},
	}))

	var b bytes.Buffer
	err := att.ToJSON(&b)
	require.NoError(t, err)

	// ToJSON output must be valid JSON and re-parseable
	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b.Bytes(), &parsed))
	require.Contains(t, parsed, "_type")
	require.Contains(t, parsed, "predicate")
}

func TestAttestationRoundTrip(t *testing.T) {
	doc := newTestVEX()
	att := &Attestation{
		Statement: &intoto.Statement{
			Type:          intoto.StatementTypeUri,
			PredicateType: string(PredicateType),
		},
		Predicate: NewPredicate(&doc),
	}
	require.NoError(t, att.AddSubjects([]*intoto.ResourceDescriptor{
		{
			Name:   "test-subject",
			Digest: map[string]string{"sha256": "deadbeef"},
		},
	}))

	var b bytes.Buffer
	require.NoError(t, att.ToJSON(&b))

	// Marshal the predicate separately and verify it matches
	// what's embedded in the full attestation (compare semantically,
	// not byte-for-byte, since indentation may differ).
	predData := att.Predicate.GetData()
	require.NotNil(t, predData)

	var full map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(b.Bytes(), &full))

	var embeddedPred map[string]any
	require.NoError(t, json.Unmarshal(full["predicate"], &embeddedPred))

	var standalonePred map[string]any
	require.NoError(t, json.Unmarshal(predData, &standalonePred))

	// The embedded predicate must be semantically equal to the standalone
	require.Equal(t, standalonePred, embeddedPred)
}

func TestAttestationMultipleSubjects(t *testing.T) {
	att := New()
	require.NoError(t, att.AddSubjects([]*intoto.ResourceDescriptor{
		{
			Name:   "pkg:oci/app@sha256:aaa",
			Digest: map[string]string{"sha256": "aaa"},
		},
		{
			Name:   "pkg:oci/app@sha256:bbb",
			Digest: map[string]string{"sha256": "bbb"},
		},
	}))

	data, err := json.Marshal(att)
	require.NoError(t, err)

	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &envelope))

	var subjects []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["subject"], &subjects))
	require.Len(t, subjects, 2)
}

func TestNewWithPredicate(t *testing.T) {
	doc := newTestVEX()
	att := New(WithPredicate(&doc))

	require.NotNil(t, att.Predicate)
	require.Equal(t, doc.ID, att.Predicate.ID)
	require.Equal(t, doc.Author, att.Predicate.Author)
	require.Len(t, att.Predicate.Statements, 1)
	require.EqualValues(t, "CVE-2024-1234", att.Predicate.Statements[0].Vulnerability.Name)

	// The intoto envelope must still be populated
	require.Equal(t, intoto.StatementTypeUri, att.GetType())
	require.Equal(t, string(PredicateType), att.Statement.GetPredicateType())

	// And the document must round-trip through the marshaled attestation
	data, err := json.Marshal(att)
	require.NoError(t, err)
	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &envelope))
	var predicate map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["predicate"], &predicate))
	var author string
	require.NoError(t, json.Unmarshal(predicate["author"], &author))
	require.Equal(t, "mailto:test@example.com", author)
}

func TestNewWithSubjects(t *testing.T) {
	s1 := &intoto.ResourceDescriptor{
		Name:   "pkg:oci/app@sha256:aaa",
		Digest: map[string]string{"sha256": "aaa"},
	}
	s2 := &intoto.ResourceDescriptor{
		Name:   "pkg:oci/app@sha256:bbb",
		Digest: map[string]string{"sha256": "bbb"},
	}
	s3 := &intoto.ResourceDescriptor{
		Name:   "pkg:oci/app@sha256:ccc",
		Digest: map[string]string{"sha256": "ccc"},
	}

	// Variadic in a single call plus a second WithSubjects call must accumulate.
	att := New(
		WithSubjects(s1, s2),
		WithSubjects(s3),
	)
	require.Len(t, att.Subject, 3)
	require.Equal(t, s1, att.Subject[0])
	require.Equal(t, s2, att.Subject[1])
	require.Equal(t, s3, att.Subject[2])
}

func TestNewWithPredicateAndSubjects(t *testing.T) {
	doc := newTestVEX()
	att := New(
		WithPredicate(&doc),
		WithSubjects(&intoto.ResourceDescriptor{
			Name:   "pkg:oci/nginx@sha256:abc123",
			Digest: map[string]string{"sha256": "abc123def456"},
		}),
		WithImportProducts(false),
	)

	data, err := json.Marshal(att)
	require.NoError(t, err)

	var envelope map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &envelope))

	var subjects []map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["subject"], &subjects))
	require.Len(t, subjects, 1)

	var predicate map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(envelope["predicate"], &predicate))
	require.Contains(t, predicate, "statements")
}

func TestNewWithPredicateNil(t *testing.T) {
	// WithPredicate(nil) should fall back to a default VEX document,
	// matching the behavior of New() with no options.
	att := New(WithPredicate(nil))
	require.NotNil(t, att.Predicate)
	require.Contains(t, att.Predicate.Context, "openvex.dev")
}

// faultyOption is a test helper that returns the given error when applied.
func faultyOption(err error) Option {
	return func(*buildOpts) error { return err }
}

func TestNewWithErrorPropagatesOptionError(t *testing.T) {
	want := errors.New("option blew up")
	att, err := NewWithError(faultyOption(want))
	require.ErrorIs(t, err, want)
	require.Nil(t, att, "no attestation should be returned when an option fails strictly")
}

func TestNewSwallowsOptionErrorsAndContinues(t *testing.T) {
	// An erroring option must not prevent later options from being applied.
	doc := newTestVEX()
	att := New(
		faultyOption(errors.New("boom")),
		WithPredicate(&doc),
		WithImportProducts(false),
	)
	require.NotNil(t, att)
	require.Equal(t, doc.ID, att.Predicate.ID, "WithPredicate after a failing option must still apply")
}

func TestAddSubjects(t *testing.T) {
	att := New()

	// Test adding valid subjects
	validSubs := []*intoto.ResourceDescriptor{
		{
			Name:   "test1",
			Digest: map[string]string{"sha256": "abc123"},
		},
		{
			Name:   "test2",
			Digest: map[string]string{"sha256": "def456"},
		},
	}

	err := att.AddSubjects(validSubs)
	require.NoError(t, err)
	require.Len(t, att.Subject, 2)
	require.Equal(t, validSubs[0], att.Subject[0])
	require.Equal(t, validSubs[1], att.Subject[1])

	// Test adding subject with no digest
	invalidSubs := []*intoto.ResourceDescriptor{
		{
			Name: "test3",
		},
	}
	err = att.AddSubjects(invalidSubs)
	require.Error(t, err)
	require.Contains(t, err.Error(), "subject test3 has no digests")
	require.Len(t, att.Subject, 2) // Length should not change
}
