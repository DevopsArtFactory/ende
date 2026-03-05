package diag

import "testing"

func TestSetEnabled(t *testing.T) {
	SetEnabled(true)
	if !Enabled() {
		t.Fatal("expected enabled after SetEnabled(true)")
	}
	SetEnabled(false)
	if Enabled() {
		t.Fatal("expected disabled after SetEnabled(false)")
	}
}

func TestParseEnv(t *testing.T) {
	truthy := []string{
		"1", "true", "yes", "y", "on", "debug",
		"TRUE", "Yes", " 1 ", "  debug  ",
	}
	for _, v := range truthy {
		if !parseEnv(v) {
			t.Errorf("parseEnv(%q) = false, want true", v)
		}
	}

	falsy := []string{"", "0", "false", "no", "off", "random"}
	for _, v := range falsy {
		if parseEnv(v) {
			t.Errorf("parseEnv(%q) = true, want false", v)
		}
	}
}

func TestDebugfDoesNotPanicWhenDisabled(t *testing.T) {
	SetEnabled(false)
	// Should not panic
	Debugf("test %s %d", "hello", 42)
}
