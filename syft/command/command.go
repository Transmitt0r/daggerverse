package command

import (
	"errors"
	"fmt"
)

var (
	ErrIndexOutOfRange = errors.New("Command index out of range")
)

type Command []string

func NewCommand(binaryName string) *Command {
	return &Command{binaryName}
}

func (c *Command) AddFlag(argName string, argValue ...string) *Command {
	for _, arg := range argValue {
		if arg != "" {
			*c = append(*c, formatArgName(argName), arg)
		}
	}
	return c
}

func (c *Command) AddCommand(command ...string) *Command {
	for _, cmd := range command {
		if cmd != "" {
			*c = append(*c, cmd)
		}
	}
	return c
}

func formatArgName(name string) string {
	return fmt.Sprintf("--%s", name)
}

func (c *Command) Len() int {
	return len(*c)
}

func (c *Command) At(index int) (string, error) {
	if index >= len(*c) {
		return "", ErrIndexOutOfRange
	}
	return (*c)[index], nil
}

func (c *Command) String() []string {
	return *c
}
