package provider

import "testing"

func TestSAMAccountNameFilter_EscapesInput(t *testing.T) {
	t.Parallel()

	if got, want := samAccountNameFilter("app*"), `(sAMAccountName=app\2a)`; got != want {
		t.Errorf("samAccountNameFilter = %q, want %q", got, want)
	}
}

func TestOUDNFromNameAndPath_EscapesName(t *testing.T) {
	t.Parallel()

	if got, want := ouDNFromNameAndPath("Sales, EMEA", "DC=example,DC=com"), `OU=Sales\, EMEA,DC=example,DC=com`; got != want {
		t.Errorf("ouDNFromNameAndPath = %q, want %q", got, want)
	}
}
