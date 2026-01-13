package responses

// AssignableUser represents a user or group that can be assigned to an issue
type AssignableUser struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}
