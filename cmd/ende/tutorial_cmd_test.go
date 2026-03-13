package main

import (
	"bytes"
	"strings"
	"testing"
)

func tutorialInput(lines ...string) string {
	return strings.Join(lines, "\n") + "\n"
}

func TestRunTutorial_English(t *testing.T) {
	input := tutorialInput("en", "tutorial-test-en", "", "", "", "", "", "")
	var out bytes.Buffer
	// keygen/register touch real keyring; errors are printed inline, not fatal.
	_ = runTutorial(strings.NewReader(input), &out)
	result := out.String()
	for _, want := range []string{
		"Ende Tutorial",
		"Step 1",
		"Step 2",
		"-t <alias>",
		"--sign-as",
		"pwgen",
		"Step 4",
		"Tutorial complete",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q\nfull output:\n%s", want, result)
		}
	}
}

func TestRunTutorial_Korean(t *testing.T) {
	input := tutorialInput("kr", "tutorial-test-kr", "", "", "", "", "", "")
	var out bytes.Buffer
	_ = runTutorial(strings.NewReader(input), &out)
	result := out.String()
	for _, want := range []string{
		"튜토리얼",
		"단계 1",
		"단계 2",
		"단계 3",
		"단계 4",
		"튜토리얼 완료",
	} {
		if !strings.Contains(result, want) {
			t.Errorf("expected output to contain %q\nfull output:\n%s", want, result)
		}
	}
}

func TestRunTutorial_InvalidLangFallsBackToEnglish(t *testing.T) {
	input := tutorialInput("jp", "tutorial-test-jp", "", "", "", "", "", "")
	var out bytes.Buffer
	_ = runTutorial(strings.NewReader(input), &out)
	if !strings.Contains(out.String(), "Ende Tutorial") {
		t.Error("expected fallback to English")
	}
}

func TestRunTutorial_SkipRegister(t *testing.T) {
	input := tutorialInput("en", "tutorial-test-skip", "", "", "", "", "", "")
	var out bytes.Buffer
	_ = runTutorial(strings.NewReader(input), &out)
	if !strings.Contains(out.String(), "skipping") {
		t.Error("expected skip message when no share token entered")
	}
}
