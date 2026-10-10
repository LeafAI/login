package mcpserver

import (
	"fmt"
	"reflect"

	"github.com/google/jsonschema-go/jsonschema"
)

// Output types per tool. Every tool also answers with the ToolError shape when isError is true; that
// shape is documented in MCP_TOOLS.md and is deliberately not part of these schemas (MCP clients
// validate structuredContent against outputSchema only for successful results).
//
// Some Archery tools answer with a pending *login* instead of their normal result while the human is
// still typing a password, so their schema is the union of the possible shapes.
type (
	// ArcheryStatusOrPending is archery_workflow_status's answer.
	ArcheryStatusOrPending struct {
		StatusOutput
		Phase    string `json:"phase,omitempty"`
		LoginID  string `json:"login_id,omitempty"`
		NextTool string `json:"next_tool,omitempty"`
	}
	// ArcheryCancelOrPending is archery_cancel's answer.
	ArcheryCancelOrPending struct {
		CancelOutput
		Phase    string `json:"phase,omitempty"`
		LoginID  string `json:"login_id,omitempty"`
		NextTool string `json:"next_tool,omitempty"`
	}
)

// outputSchema infers the JSON Schema of a result type. Result structs serve success and pending
// answers alike (and Archery tools can answer with a pending login), so no field is "required" and
// unknown fields of objects stay allowed. Typed maps (headers, tokens) keep their value type.
func outputSchema(t reflect.Type) (*jsonschema.Schema, error) {
	s, err := jsonschema.ForType(t, nil)
	if err != nil {
		return nil, fmt.Errorf("output schema for %s: %w", t, err)
	}
	relax(s)
	return s, nil
}

func relax(s *jsonschema.Schema) {
	if s == nil {
		return
	}
	s.Required = nil
	if len(s.Properties) > 0 { // a struct: allow fields added later; a map keeps its value schema
		s.AdditionalProperties = nil
	}
	for _, p := range s.Properties {
		relax(p)
	}
	relax(s.Items)
	for _, d := range s.Defs {
		relax(d)
	}
}
