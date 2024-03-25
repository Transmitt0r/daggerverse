package command_test

import (
	"github.com/Transmitt0r/daggerverse/syft/command"
	"testing"
)

const testBinary = "test"

func TestNewCommand(t *testing.T) {
	cmd := command.NewCommand(testBinary)

	if cmd.Len() != 1 {
		t.Fatalf("Expected command to have a lenght of %d, got %d", 1, cmd.Len())
	}

	zero, err := cmd.At(0)
	if err != nil {
		t.Fatal(err)
	}

	if zero != testBinary {
		t.Errorf("Expected element to be equal to %s, got %s", testBinary, zero)
	}
}

func TestAddFlag(t *testing.T) {
	cmd := command.NewCommand(testBinary)

	cmd.AddFlag("test-flag", "flag-value")

	if cmd.Len() != 3 {
		t.Fatalf("Expected command to have a lenght of %d, got %d", 3, cmd.Len())
	}

	var one, two string
	var err error

	if one, err = cmd.At(1); err != nil {
		t.Fatal(err)
	}

	if two, err = cmd.At(2); err != nil {
		t.Fatal(err)
	}

	if one != "--test-flag" || two != "flag-value" {
		t.Errorf("Expected flag to be --test-flag flag-value but got %s %s", one, two)
	}

	cmd.AddFlag("test-flag-variadic", "value1", "", "value3")
	if cmd.Len() != 7 {
		t.Fatalf("Expected command to have a lenght of %d, got %d", 7, cmd.Len())
	}
}

func TestAddCommand(t *testing.T) {
	cmd := command.NewCommand(testBinary)

	cmd.AddCommand("this")

	if cmd.Len() != 2 {
		t.Fatalf("Expected command to have a lenght of %d, got %d", 2, cmd.Len())
	}

	one, err := cmd.At(1)
	if err != nil {
		t.Fatal(err)
	}

	if one != "this" {
		t.Errorf("Expected element to be equal to %s, got %s", "this", one)
	}

	cmd.AddCommand("and", "", "that")
	if cmd.Len() != 4 {
		t.Errorf("Expected command to have a length of %d, got %d", 4, cmd.Len())
	}
}
