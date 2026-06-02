package validation

// Issue represents a single expected problem — input validation, business rule,
// constraint violation, auth failure, etc. Anything that isn't a Go error
// (which represents something truly unexpected).
type Issue struct {
	Field      string `json:"field,omitempty"`      // input field (optional — not all issues are field-specific)
	Code       string `json:"code"`                 // machine-readable: "required", "duplicate", "plan_limit_reached"
	Message    string `json:"message,omitempty"`    // user-facing: "Please enter a valid email"
	DevMessage string `json:"devMessage,omitempty"` // developer-facing: "email failed RFC 5322 parse"
	Extra      any    `json:"extra,omitempty"`      // metadata: {"maxLength": 50}
}

// Result collects zero or more issues. A zero-value Result means "ok".
type Result struct {
	Issues []Issue `json:"issues,omitempty"`
	Status int     `json:"-"` // suggested HTTP status (default 400, never serialized)
}

// NewIssue creates a Result with a single field-level issue.
func NewIssue(field, code, message string) *Result {
	return &Result{Issues: []Issue{{Field: field, Code: code, Message: message}}}
}

// WithField sets the field on the last issue.
func (r *Result) WithField(field string) *Result {
	if len(r.Issues) > 0 {
		r.Issues[len(r.Issues)-1].Field = field
	}
	return r
}

// WithMessage sets the user-facing message on the last issue.
func (r *Result) WithMessage(message string) *Result {
	if len(r.Issues) > 0 {
		r.Issues[len(r.Issues)-1].Message = message
	}
	return r
}

// WithDevMessage sets the developer-facing message on the last issue.
func (r *Result) WithDevMessage(devMessage string) *Result {
	if len(r.Issues) > 0 {
		r.Issues[len(r.Issues)-1].DevMessage = devMessage
	}
	return r
}

// WithExtra sets metadata on the last issue.
func (r *Result) WithExtra(extra any) *Result {
	if len(r.Issues) > 0 {
		r.Issues[len(r.Issues)-1].Extra = extra
	}
	return r
}

// WithStatus sets the suggested HTTP status on the result.
func (r *Result) WithStatus(status int) *Result {
	r.Status = status
	return r
}

// AddFieldIssue appends a field-level issue to the result.
func (r *Result) AddFieldIssue(field, code, message string) *Result {
	r.Issues = append(r.Issues, Issue{Field: field, Code: code, Message: message})
	return r
}

// AddIssue appends a non-field issue to the result.
func (r *Result) AddIssue(code, message string) *Result {
	r.Issues = append(r.Issues, Issue{Code: code, Message: message})
	return r
}

// Ok returns true if there are no issues.
func (r *Result) Ok() bool {
	return len(r.Issues) == 0
}
