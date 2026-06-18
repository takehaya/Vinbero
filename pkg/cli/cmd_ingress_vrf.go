package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func ingressVrfCommand() *cli.Command {
	return &cli.Command{
		Name:    "ingress-vrf",
		Aliases: []string{"ivrf"},
		Usage:   "Manage the ingress VRF front door ({interface, VLAN} -> vrf_id)",
		Subcommands: []*cli.Command{
			{
				Name:  "bind",
				Usage: "Bind an access circuit {interface, vlan} to a vrf_id (0 = global/underlay)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "interface", Required: true, Usage: "Ingress interface name"},
					&cli.UintFlag{Name: "vlan", Usage: "VLAN ID (0 = untagged)"},
					&cli.UintFlag{Name: "vrf", Required: true, Usage: "Ingress VRF id (0 = global/default VRF)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.IngVrf.IngressVrfBind(context.Background(),
						connect.NewRequest(&v1.IngressVrfBindRequest{
							Entries: []*v1.IngressVrfEntry{{
								InterfaceName: c.String("interface"),
								Vlan:          uint32(c.Uint("vlan")),
								VrfId:         uint32(c.Uint("vrf")),
							}},
						}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Bound, resp.Msg.Errors, "ingress VRF binding")
				},
			},
			{
				Name:  "unbind",
				Usage: "Remove an access circuit binding (by interface + vlan)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "interface", Required: true, Usage: "Ingress interface name"},
					&cli.UintFlag{Name: "vlan", Usage: "VLAN ID (0 = untagged)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.IngVrf.IngressVrfUnbind(context.Background(),
						connect.NewRequest(&v1.IngressVrfUnbindRequest{
							Entries: []*v1.IngressVrfEntry{{
								InterfaceName: c.String("interface"),
								Vlan:          uint32(c.Uint("vlan")),
							}},
						}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Unbound, resp.Msg.Errors, "ingress VRF binding")
				},
			},
			{
				Name:  "policy",
				Usage: "Set the global ingress policy (default-deny)",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "default-deny", Usage: "Drop unmapped ACs instead of falling into vrf 0 (global)"},
					&cli.StringFlag{Name: "deny-action", Value: "drop", Usage: "Action for unmapped ACs under default-deny: drop | pass"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.IngVrf.IngressVrfSetPolicy(context.Background(),
						connect.NewRequest(&v1.IngressVrfSetPolicyRequest{
							Policy: &v1.IngressVrfPolicy{
								DefaultDeny: c.Bool("default-deny"),
								DenyAction:  c.String("deny-action"),
							},
						}))
					if err != nil {
						return err
					}
					p := resp.Msg.GetPolicy()
					fmt.Printf("ingress policy: default_deny=%t deny_action=%s\n", p.GetDefaultDeny(), p.GetDenyAction())
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List ingress VRF bindings and the global policy",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.IngVrf.IngressVrfList(context.Background(),
						connect.NewRequest(&v1.IngressVrfListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg)
					}
					if p := resp.Msg.GetPolicy(); p != nil {
						fmt.Printf("policy: default_deny=%t deny_action=%s\n", p.GetDefaultDeny(), p.GetDenyAction())
					}
					headers := []string{"INTERFACE", "VLAN", "VRF_ID"}
					var rows [][]string
					for _, e := range resp.Msg.Entries {
						rows = append(rows, []string{
							e.InterfaceName,
							fmt.Sprintf("%d", e.Vlan),
							fmt.Sprintf("%d", e.VrfId),
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}
