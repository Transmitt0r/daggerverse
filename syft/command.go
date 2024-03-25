package main

import (
	"fmt"
)

type Command []string

func NewCommand(binaryName string) Command {
	return Command{binaryName}
}

func (c Command) AddFlag(argName string, argValue ...string) Command {
	for _, arg := range argValue {
		if arg != "" {
			c = append(c, formatArgName(argName), arg)
		}
	}
	return c
}

func (c Command) AddCommand(command ...string) Command {
	for _, cmd := range command {
		if cmd != "" {
			c = append(c, cmd)
		}
	}
	return c
}

func formatArgName(name string) string {
	return fmt.Sprintf("--%s", name)
}
