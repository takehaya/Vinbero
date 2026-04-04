package completion

import (
	_ "embed"
	"fmt"
	"strings"

	"github.com/urfave/cli/v2"
)

//go:embed bash_completion.sh
var bashScript string

//go:embed zsh_completion.sh
var zshScript string

func RenderBash(prog string) string {
	return strings.ReplaceAll(bashScript, "{{prog}}", prog)
}

func RenderZsh(prog string) string {
	return strings.ReplaceAll(zshScript, "{{prog}}", prog)
}

func Command() *cli.Command {
	return &cli.Command{
		Name:  "completion",
		Usage: "Output shell completion script",
		Subcommands: []*cli.Command{
			{
				Name:  "bash",
				Usage: "Output bash completion script",
				Action: func(c *cli.Context) error {
					fmt.Print(RenderBash(c.App.Name))
					return nil
				},
			},
			{
				Name:  "zsh",
				Usage: "Output zsh completion script",
				Action: func(c *cli.Context) error {
					fmt.Print(RenderZsh(c.App.Name))
					return nil
				},
			},
		},
	}
}
