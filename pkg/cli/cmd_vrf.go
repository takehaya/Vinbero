package cli

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

// vrfIngressSubcommands are the VRF ingress-facet subcommands (access-circuit
// membership + default-deny policy), appended to the `vrf` command alongside
// the kernel-device subcommands (create/delete/list) so there is one `vrf`
// command surface.
func vrfIngressSubcommands() []*cli.Command {
	return []*cli.Command{
		{
			Name:  "ac-add",
			Usage: "Add an ingress access circuit {interface, vlan} to a VRF (creates the VRF)",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "vrf", Required: true, Usage: "VRF name"},
				&cli.StringFlag{Name: "interface", Required: true, Usage: "Ingress interface name"},
				&cli.UintFlag{Name: "vlan", Usage: "VLAN ID (0 = untagged)"},
			},
			Action: func(c *cli.Context) error {
				clients := clientsFromContext(c)
				resp, err := clients.Vrf.VrfAcAdd(context.Background(),
					connect.NewRequest(&v1.VrfAcAddRequest{
						Name: c.String("vrf"),
						Ac:   &v1.VrfAc{InterfaceName: c.String("interface"), Vlan: uint32(c.Uint("vlan"))},
					}))
				if err != nil {
					return err
				}
				v := resp.Msg.GetVrf()
				fmt.Printf("vrf %s (vrf_id=%d): %d access circuit(s)\n", v.GetName(), v.GetVrfId(), len(v.GetAcs()))
				return nil
			},
		},
		{
			Name:  "ac-remove",
			Usage: "Remove an ingress access circuit from a VRF",
			Flags: []cli.Flag{
				&cli.StringFlag{Name: "vrf", Required: true, Usage: "VRF name"},
				&cli.StringFlag{Name: "interface", Required: true, Usage: "Ingress interface name"},
				&cli.UintFlag{Name: "vlan", Usage: "VLAN ID (0 = untagged)"},
			},
			Action: func(c *cli.Context) error {
				clients := clientsFromContext(c)
				_, err := clients.Vrf.VrfAcRemove(context.Background(),
					connect.NewRequest(&v1.VrfAcRemoveRequest{
						Name: c.String("vrf"),
						Ac:   &v1.VrfAc{InterfaceName: c.String("interface"), Vlan: uint32(c.Uint("vlan"))},
					}))
				if err != nil {
					return err
				}
				fmt.Println("removed")
				return nil
			},
		},
		{
			Name:  "policy",
			Usage: "Set the global ingress policy (default-deny)",
			Flags: []cli.Flag{
				&cli.BoolFlag{Name: "default-deny", Usage: "Drop unmapped ACs instead of falling into the global VRF (vrf 0)"},
				&cli.StringFlag{Name: "deny-action", Value: "drop", Usage: "Action for unmapped ACs under default-deny: drop | pass"},
			},
			Action: func(c *cli.Context) error {
				clients := clientsFromContext(c)
				resp, err := clients.Vrf.VrfSetPolicy(context.Background(),
					connect.NewRequest(&v1.VrfSetPolicyRequest{
						Policy: &v1.VrfPolicy{
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
			Name:  "show",
			Usage: "Show VRFs (ingress facet) and the global policy",
			Action: func(c *cli.Context) error {
				clients := clientsFromContext(c)
				resp, err := clients.Vrf.VrfShow(context.Background(),
					connect.NewRequest(&v1.VrfShowRequest{}))
				if err != nil {
					return err
				}
				if useJSON(c) {
					return printJSON(resp.Msg)
				}
				if p := resp.Msg.GetPolicy(); p != nil {
					fmt.Printf("policy: default_deny=%t deny_action=%s\n", p.GetDefaultDeny(), p.GetDenyAction())
				}
				headers := []string{"VRF", "VRF_ID", "INTERFACE", "VLAN"}
				var rows [][]string
				for _, v := range resp.Msg.Vrfs {
					if len(v.Acs) == 0 {
						rows = append(rows, []string{v.Name, fmt.Sprintf("%d", v.VrfId), "-", "-"})
						continue
					}
					for _, ac := range v.Acs {
						rows = append(rows, []string{
							v.Name, fmt.Sprintf("%d", v.VrfId), ac.InterfaceName, fmt.Sprintf("%d", ac.Vlan),
						})
					}
				}
				printTable(headers, rows)
				return nil
			},
		},
	}
}
