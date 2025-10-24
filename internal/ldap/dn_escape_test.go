package ldap

import (
	"testing"
)

func TestEscapeDNValue(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "simple value no escaping needed",
			input:    "JohnDoe",
			expected: "JohnDoe",
		},
		{
			name:     "value with space in middle",
			input:    "John Doe",
			expected: "John Doe",
		},
		{
			name:     "comma in value",
			input:    "Doe, John",
			expected: "Doe\\, John",
		},
		{
			name:     "plus sign",
			input:    "CN=John+SN=Doe",
			expected: "CN=John\\+SN=Doe",
		},
		{
			name:     "double quote",
			input:    "John \"Doe\"",
			expected: "John \\\"Doe\\\"",
		},
		{
			name:     "backslash",
			input:    "John\\Doe",
			expected: "John\\\\Doe",
		},
		{
			name:     "angle brackets",
			input:    "John<>Doe",
			expected: "John\\<\\>Doe",
		},
		{
			name:     "semicolon",
			input:    "John;Doe",
			expected: "John\\;Doe",
		},
		{
			name:     "leading space",
			input:    " John",
			expected: "\\ John",
		},
		{
			name:     "trailing space",
			input:    "John ",
			expected: "John\\ ",
		},
		{
			name:     "leading and trailing spaces",
			input:    " John ",
			expected: "\\ John\\ ",
		},
		{
			name:     "leading hash",
			input:    "#123",
			expected: "\\#123",
		},
		{
			name:     "hash in middle",
			input:    "John#123",
			expected: "John#123",
		},
		{
			name:     "multiple special characters",
			input:    "Doe, John <admin>",
			expected: "Doe\\, John \\<admin\\>",
		},
		{
			name:     "all special characters",
			input:    ",+\"\\<>;",
			expected: "\\,\\+\\\"\\\\\\<\\>\\;",
		},
		{
			name:     "real world example - name with comma",
			input:    "Smith, John",
			expected: "Smith\\, John",
		},
		{
			name:     "real world example - name with quotes",
			input:    "John \"Johnny\" Doe",
			expected: "John \\\"Johnny\\\" Doe",
		},
		{
			name:     "real world example - complex name",
			input:    "Smith, John <john@example.com>",
			expected: "Smith\\, John \\<john@example.com\\>",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := EscapeDNValue(tc.input)
			if result != tc.expected {
				t.Errorf("EscapeDNValue(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestUnescapeDNValue(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "no escaping",
			input:    "JohnDoe",
			expected: "JohnDoe",
		},
		{
			name:     "escaped comma",
			input:    "Doe\\, John",
			expected: "Doe, John",
		},
		{
			name:     "escaped plus",
			input:    "CN=John\\+SN=Doe",
			expected: "CN=John+SN=Doe",
		},
		{
			name:     "escaped quotes",
			input:    "John \\\"Doe\\\"",
			expected: "John \"Doe\"",
		},
		{
			name:     "escaped backslash",
			input:    "John\\\\Doe",
			expected: "John\\Doe",
		},
		{
			name:     "escaped angle brackets",
			input:    "John\\<\\>Doe",
			expected: "John<>Doe",
		},
		{
			name:     "escaped leading space",
			input:    "\\ John",
			expected: " John",
		},
		{
			name:     "escaped trailing space",
			input:    "John\\ ",
			expected: "John ",
		},
		{
			name:     "escaped leading hash",
			input:    "\\#123",
			expected: "#123",
		},
		{
			name:     "multiple escaped characters",
			input:    "Doe\\, John \\<admin\\>",
			expected: "Doe, John <admin>",
		},
		{
			name:     "hex escaped null byte",
			input:    "John\\00Doe",
			expected: "John\x00Doe",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := UnescapeDNValue(tc.input)
			if result != tc.expected {
				t.Errorf("UnescapeDNValue(%q) = %q, expected %q", tc.input, result, tc.expected)
			}
		})
	}
}

func TestEscapeUnescapeRoundtrip(t *testing.T) {
	testCases := []string{
		"John Doe",
		"Doe, John",
		"John \"Johnny\" Doe",
		"John\\Doe",
		"John<>Doe",
		" John ",
		"#123",
		"Smith, John <john@example.com>",
		",+\"\\<>;",
	}

	for _, tc := range testCases {
		t.Run(tc, func(t *testing.T) {
			escaped := EscapeDNValue(tc)
			unescaped := UnescapeDNValue(escaped)
			if unescaped != tc {
				t.Errorf("Roundtrip failed for %q: escaped=%q, unescaped=%q", tc, escaped, unescaped)
			}
		})
	}
}

func TestNeedsDNEscaping(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "empty string",
			input:    "",
			expected: false,
		},
		{
			name:     "simple value",
			input:    "JohnDoe",
			expected: false,
		},
		{
			name:     "value with space in middle",
			input:    "John Doe",
			expected: false,
		},
		{
			name:     "comma in value",
			input:    "Doe, John",
			expected: true,
		},
		{
			name:     "leading space",
			input:    " John",
			expected: true,
		},
		{
			name:     "trailing space",
			input:    "John ",
			expected: true,
		},
		{
			name:     "leading hash",
			input:    "#123",
			expected: true,
		},
		{
			name:     "hash in middle",
			input:    "John#123",
			expected: false,
		},
		{
			name:     "plus sign",
			input:    "John+Doe",
			expected: true,
		},
		{
			name:     "double quote",
			input:    "John\"Doe",
			expected: true,
		},
		{
			name:     "backslash",
			input:    "John\\Doe",
			expected: true,
		},
		{
			name:     "angle bracket",
			input:    "John<Doe",
			expected: true,
		},
		{
			name:     "semicolon",
			input:    "John;Doe",
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := NeedsDNEscaping(tc.input)
			if result != tc.expected {
				t.Errorf("NeedsDNEscaping(%q) = %v, expected %v", tc.input, result, tc.expected)
			}
		})
	}
}

// Benchmark tests.
func BenchmarkEscapeDNValue_NoEscaping(b *testing.B) {
	value := "JohnDoe"
	for b.Loop() {
		_ = EscapeDNValue(value)
	}
}

func BenchmarkEscapeDNValue_WithEscaping(b *testing.B) {
	value := "Doe, John <john@example.com>"
	for b.Loop() {
		_ = EscapeDNValue(value)
	}
}

func BenchmarkUnescapeDNValue_NoEscaping(b *testing.B) {
	value := "JohnDoe"
	for b.Loop() {
		_ = UnescapeDNValue(value)
	}
}

func BenchmarkUnescapeDNValue_WithEscaping(b *testing.B) {
	value := "Doe\\, John \\<john@example.com\\>"
	for b.Loop() {
		_ = UnescapeDNValue(value)
	}
}

func BenchmarkNeedsDNEscaping_False(b *testing.B) {
	value := "JohnDoe"
	for b.Loop() {
		_ = NeedsDNEscaping(value)
	}
}

func BenchmarkNeedsDNEscaping_True(b *testing.B) {
	value := "Doe, John"
	for b.Loop() {
		_ = NeedsDNEscaping(value)
	}
}
