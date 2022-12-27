package server

const (
	ListSecretsURL   = "/api/secrets/"
	GetSecretsURL    = "/api/secrets/:name/"
	UpdateSecretsURL = "/api/secrets/:name/"
	DeleteSecretsURL = "/api/secrets/:name/"
)

// ListSecretsResponse is the JSON response format for ListSecretsURL
type ListSecretsResponse struct {
	Secrets []string `json:"secrets"`
}

// ListSecretsResponse is the JSON response format for GetSecretsURL
type GetSecretsResponse struct {
	Name     string `json:"name"`
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Email    string `json:"email"`
	Notes    string `json:"notes"`
}

// UpdateSecretsRequest is the JSON request format for UpdateSecretsURL
type UpdateSecretsRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	Email    string `json:"email"`
	Notes    string `json:"notes"`
}

// UpdateSecretsResponse is the JSON response format for UpdateSecretsURL
type UpdateSecretsResponse struct {
	Name string `json:"name"`
}

// DeleteSecretsResponse is the JSON response format for DeleteSecretsURL
type DeleteSecretsResponse struct {
	Name string `json:"name"`
}

// ErrorResponse is the JSON response format for all non 2xx response codes
type ErrorResponse struct {
	Error string `json:"error"`
}
