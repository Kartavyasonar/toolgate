package redact

import "testing"

func TestRedact(t *testing.T) {
	keys := []string{"password", "api_key"}
	input := map[string]any{
		"username": "admin",
		"password": "supersecret",
		"nested": map[string]any{
			"api_key": "12345",
			"data":    "safe",
		},
	}
	
	result, count := Redact(input, keys)
	if count != 2 {
		t.Errorf("count = %d, want 2", count)
	}
	
	m := result.(map[string]any)
	if m["password"] != "[REDACTED]" {
		t.Errorf("password not redacted")
	}
	nested := m["nested"].(map[string]any)
	if nested["api_key"] != "[REDACTED]" {
		t.Errorf("nested api_key not redacted")
	}
	if nested["data"] != "safe" {
		t.Errorf("safe data modified")
	}
}