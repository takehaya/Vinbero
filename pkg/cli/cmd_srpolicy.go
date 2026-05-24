package cli

import (
	"context"
	"fmt"
	"os"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func parseSegmentsCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// reportSRPolicyErrors prints per-item errors and a success count, and
// returns a non-zero error when any item failed (for scripting).
func reportSRPolicyErrors(total int, errs []*v1.OperationError, verb string) error {
	for _, e := range errs {
		fmt.Fprintf(os.Stderr, "Error [%s]: %s\n", e.TriggerPrefix, e.Reason)
	}
	if ok := total - len(errs); ok > 0 {
		fmt.Printf("SR Policy %s: %d\n", verb, ok)
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d SR Policy %s operation(s) failed", len(errs), verb)
	}
	return nil
}

func srPolicyDefFromFlags(c *cli.Context) *v1.SrPolicyDef {
	return &v1.SrPolicyDef{
		Color:      uint32(c.Uint("color")),
		Endpoint:   c.String("endpoint"),
		Segments:   parseSegmentsCSV(c.String("segments")),
		Preference: uint32(c.Uint("preference")),
	}
}

func srPolicyCommand() *cli.Command {
	defFlags := []cli.Flag{
		&cli.UintFlag{Name: "color", Required: true, Usage: "SR Policy color (matched by the Color Extended Community)"},
		&cli.StringFlag{Name: "endpoint", Required: true, Usage: "Endpoint IPv6 (= egress PE BGP next hop)"},
		&cli.StringFlag{Name: "segments", Required: true, Usage: "Comma-separated transport SRv6 SIDs, e.g. fd00:2::1,fd00:2::2"},
		&cli.UintFlag{Name: "preference", Value: 0, Usage: "Candidate path preference (0 = RFC default 100)"},
	}
	keyFlags := []cli.Flag{
		&cli.UintFlag{Name: "color", Required: true, Usage: "SR Policy color"},
		&cli.StringFlag{Name: "endpoint", Required: true, Usage: "Endpoint IPv6"},
	}
	return &cli.Command{
		Name:    "sr-policy",
		Aliases: []string{"srp"},
		Usage:   "Manage SR Policies for color-based steering",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Define a local SR Policy and install it into the data plane",
				Flags: defFlags,
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.SrPolicy.SrPolicyCreate(context.Background(),
						connect.NewRequest(&v1.SrPolicyCreateRequest{Policies: []*v1.SrPolicyDef{srPolicyDefFromFlags(c)}}))
					if err != nil {
						return err
					}
					return reportSRPolicyErrors(1, resp.Msg.Errors, "created")
				},
			},
			{
				Name:  "update",
				Usage: "Replace a local SR Policy's transport / preference",
				Flags: defFlags,
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.SrPolicy.SrPolicyUpdate(context.Background(),
						connect.NewRequest(&v1.SrPolicyUpdateRequest{Policies: []*v1.SrPolicyDef{srPolicyDefFromFlags(c)}}))
					if err != nil {
						return err
					}
					return reportSRPolicyErrors(1, resp.Msg.Errors, "updated")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a local SR Policy (BGP-learned policies are read-only)",
				Flags: keyFlags,
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.SrPolicy.SrPolicyDelete(context.Background(),
						connect.NewRequest(&v1.SrPolicyDeleteRequest{Keys: []*v1.SrPolicyKey{{
							Color:    uint32(c.Uint("color")),
							Endpoint: c.String("endpoint"),
						}}}))
					if err != nil {
						return err
					}
					return reportSRPolicyErrors(1, resp.Msg.Errors, "deleted")
				},
			},
			{
				Name:  "list",
				Usage: "List SR Policies (local + BGP-learned)",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.SrPolicy.SrPolicyList(context.Background(),
						connect.NewRequest(&v1.SrPolicyListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Entries)
					}
					headers := []string{"COLOR", "ENDPOINT", "POLICY_ID", "ORIGIN", "PREF", "ACTIVE", "SEGMENTS"}
					var rows [][]string
					for _, e := range resp.Msg.Entries {
						if len(e.Candidates) == 0 {
							rows = append(rows, []string{
								fmt.Sprintf("%d", e.Color), e.Endpoint, fmt.Sprintf("%d", e.PolicyId),
								"-", "-", "-", "(awaiting candidate)",
							})
							continue
						}
						for _, cand := range e.Candidates {
							active := ""
							if cand.Active {
								active = "*"
							}
							rows = append(rows, []string{
								fmt.Sprintf("%d", e.Color), e.Endpoint, fmt.Sprintf("%d", e.PolicyId),
								formatSRPolicyOrigin(cand.Origin),
								fmt.Sprintf("%d", cand.Preference),
								active,
								strings.Join(cand.Segments, ","),
							})
						}
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}

func formatSRPolicyOrigin(o v1.SrPolicyOrigin) string {
	return formatProtoEnum(o, "SR_POLICY_ORIGIN_")
}
