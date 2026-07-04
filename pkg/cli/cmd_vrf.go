package cli

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

// splitMembers parses a comma-separated interface list, trimming whitespace
// and dropping empty elements: "eth1, eth2," must not yield " eth2" (which
// fails netlink name resolution) or a trailing empty member.
func splitMembers(s string) []string {
	var out []string
	for _, m := range strings.Split(s, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// vrfCommand is the single VRF operator surface, covering both facets of the
// VRF object: the kernel device (create/delete) and the ingress facet
// (ac-add/ac-remove/policy). show renders both.
func vrfCommand() *cli.Command {
	return &cli.Command{
		Name:  "vrf",
		Usage: "Manage VRFs (kernel device + ingress access-circuit membership)",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create (or adopt) a kernel VRF device; allocates the VRF's vrf_id",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "VRF name"},
					&cli.UintFlag{Name: "table-id", Required: true, Usage: "Routing table ID"},
					&cli.StringFlag{Name: "members", Usage: "Member interfaces (comma-separated)"},
					&cli.BoolFlag{Name: "enable-l3mdev-rule", Usage: "Add l3mdev routing rule"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					members := splitMembers(c.String("members"))
					resp, err := clients.Vrf.VrfCreate(context.Background(),
						connect.NewRequest(&v1.VrfCreateRequest{Vrfs: []*v1.Vrf{{
							Name:             c.String("name"),
							TableId:          uint32(c.Uint("table-id")),
							Members:          members,
							EnableL3MdevRule: c.Bool("enable-l3mdev-rule"),
						}}}))
					if err != nil {
						return err
					}
					for _, v := range resp.Msg.Created {
						fmt.Printf("vrf %s created (vrf_id=%d table_id=%d ifindex=%d)\n",
							v.GetName(), v.GetVrfId(), v.GetTableId(), v.GetIfindex())
					}
					// The per-VRF lines above are the success output; hand
					// printOperationResult only the errors so it does not
					// print a redundant count line.
					return printOperationResult([]*v1.Vrf(nil), resp.Msg.Errors, "VRF")
				},
			},
			{
				Name:  "delete",
				Usage: "Delete a VRF (device + identity); refused while a SID, AC or vrf-bgp binding references it",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Vrf.VrfDelete(context.Background(),
						connect.NewRequest(&v1.VrfDeleteRequest{Names: []string{c.String("name")}}))
					if err != nil {
						return err
					}
					if len(resp.Msg.DeletedNames) > 0 {
						fmt.Printf("Deleted: %s\n", strings.Join(resp.Msg.DeletedNames, ", "))
					}
					// Same single-success-line convention as create above.
					return printOperationResult([]string(nil), resp.Msg.Errors, "VRF", "deleted")
				},
			},
			{
				Name:  "bridge-attach",
				Usage: "Attach the L2 bridge-domain facet: create (or adopt) the kernel bridge on a VRF",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true, Usage: "VRF name"},
					&cli.StringFlag{Name: "name", Required: true, Usage: "Bridge device name"},
					&cli.UintFlag{Name: "bd-id", Required: true, Usage: "Bridge Domain ID (1..65535)"},
					&cli.StringFlag{Name: "members", Usage: "Member interfaces (comma-separated)"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Vrf.VrfBridgeAttach(context.Background(),
						connect.NewRequest(&v1.VrfBridgeAttachRequest{
							VrfName: c.String("vrf"),
							Bridge: &v1.Bridge{
								Name:    c.String("name"),
								BdId:    uint32(c.Uint("bd-id")),
								Members: splitMembers(c.String("members")),
							},
						}))
					if err != nil {
						return err
					}
					b := resp.Msg.GetVrf().GetBridge()
					fmt.Printf("vrf %s: bridge %s attached (bd_id=%d ifindex=%d)\n",
						resp.Msg.GetVrf().GetName(), b.GetName(), b.GetBdId(), b.GetIfindex())
					return nil
				},
			},
			{
				Name:  "bridge-detach",
				Usage: "Detach the L2 facet: delete the kernel bridge (refused while a SID references it)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true, Usage: "VRF name"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					_, err := clients.Vrf.VrfBridgeDetach(context.Background(),
						connect.NewRequest(&v1.VrfBridgeDetachRequest{VrfName: c.String("vrf")}))
					if err != nil {
						return err
					}
					fmt.Println("detached")
					return nil
				},
			},
			{
				Name:  "ac-add",
				Usage: "Add an ingress access circuit {interface, vlan} to a VRF (creates the VRF)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true, Usage: "VRF name (reserved name \"global\" maps the AC to the underlay, vrf_id 0)"},
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
				Usage: "Show VRFs (kernel device + bridge + ingress facets) and the global policy",
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
					headers := []string{"VRF", "VRF_ID", "TABLE_ID", "IFINDEX", "BD_ID", "BRIDGE", "INTERFACE", "VLAN"}
					var rows [][]string
					for _, v := range resp.Msg.Vrfs {
						// Facet columns repeat per AC row; "-" = the facet is absent.
						tableID, ifindex := "-", "-"
						if v.GetIfindex() != 0 {
							tableID = fmt.Sprintf("%d", v.GetTableId())
							ifindex = fmt.Sprintf("%d", v.GetIfindex())
						}
						bdID, bridge := "-", "-"
						if b := v.GetBridge(); b != nil {
							bdID = fmt.Sprintf("%d", b.GetBdId())
							bridge = b.GetName()
						}
						if len(v.Acs) == 0 {
							rows = append(rows, []string{v.Name, fmt.Sprintf("%d", v.VrfId), tableID, ifindex, bdID, bridge, "-", "-"})
							continue
						}
						for _, ac := range v.Acs {
							rows = append(rows, []string{
								v.Name, fmt.Sprintf("%d", v.VrfId), tableID, ifindex, bdID, bridge,
								ac.InterfaceName, fmt.Sprintf("%d", ac.Vlan),
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
