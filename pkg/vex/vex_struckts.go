type VEX struct {
	Metadata
	Statements []Statement `json:"statements"`
}

// The Metadata type represents the metadata associated with a VEX document.
type Metadata struct {
	// Context is the URL pointing to the jsonld context definition
	Context string `json:"@context"`

	// ID is the identifying string for the VEX document. This should be unique per
	// document.
	ID string `json:"@id"`

	// Author is the identifier for the author of the VEX statement, ideally a common
	// name, may be a URI. [author] is an individual or organization. [author]
	// identity SHOULD be cryptographically associated with the signature of the VEX
	// statement or document or transport.
	Author string `json:"author"`

	// AuthorRole describes the role of the document Author.
	AuthorRole string `json:"role,omitempty"`

	// Timestamp defines the time at which the document was issued.
	Timestamp *time.Time `json:"timestamp"`

	// LastUpdated marks the time when the document had its last update. When the
	// document changes both version and this field should be updated.
	LastUpdated *time.Time `json:"last_updated,omitempty"`

	// Version is the document version. It must be incremented when any content
	// within the VEX document changes, including any VEX statements included within
	// the VEX document.
	Version int `json:"version"`

	// Tooling expresses how the VEX document and contained VEX statements were
	// generated. It's optional. It may specify tools or automated processes used in
	// the document or statement generation.
	Tooling string `json:"tooling,omitempty"`

	// Supplier is an optional field.
	Supplier string `json:"supplier,omitempty"`
}