package cli

import (
	"context"
	"fmt"
	"math"
	"strings"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
)

func vrfBgpCommand() *cli.Command {
	return &cli.Command{
		Name:    "vrf-bgp",
		Aliases: []string{"vbgp"},
		Usage:   "Manage VRF <-> BGP route-target bindings",
		Subcommands: []*cli.Command{
			{
				Name:  "bind",
				Usage: "Bind a VRF to its BGP route-target policy",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true, Usage: "VRF device name"},
					&cli.StringFlag{Name: "import-rts", Usage: "Import route targets (comma-separated, e.g. 65000:100,65000:101)"},
					&cli.StringFlag{Name: "export-rts", Usage: "Export route targets (comma-separated)"},
					&cli.StringFlag{Name: "default-locator", Usage: "Locator name for this VRF's local SIDs"},
					&cli.UintFlag{Name: "bd-id", Usage: "Bridge domain for EVPN routes matching import-rts (0 = L3VPN-only)"},
					&cli.StringFlag{Name: "rd", Usage: "Route distinguisher for auto-advertised local prefixes (e.g. 65100:200)"},
					&cli.StringFlag{Name: "redistribute", Usage: "Auto-advertise protocols (comma-separated: connected,static)"},
					&cli.UintFlag{Name: "max-prefixes", Usage: "Cap on auto-advertised prefixes for this VRF (0 = unlimited)"},
				},
				Action: func(c *cli.Context) error {
					// c.Uint may be 64-bit; reject out-of-range bd_id here so a
					// large value cannot fold into uint32 and slip past the
					// server's uint16 range check, binding an unintended BD.
					bdID := c.Uint("bd-id")
					if bdID > math.MaxUint16 {
						return fmt.Errorf("bd-id %d out of range (max %d)", bdID, math.MaxUint16)
					}
					maxPfx := c.Uint("max-prefixes")
					if maxPfx > math.MaxUint32 {
						return fmt.Errorf("max-prefixes %d out of range (max %d)", maxPfx, uint32(math.MaxUint32))
					}
					b := &v1.VrfBgpBinding{
						VrfName:        c.String("vrf"),
						ImportRts:      csvFlag(c.String("import-rts")),
						ExportRts:      csvFlag(c.String("export-rts")),
						DefaultLocator: c.String("default-locator"),
						BdId:           uint32(bdID),
						Rd:             c.String("rd"),
						Redistribute:   csvFlag(c.String("redistribute")),
						MaxPrefixes:    uint32(maxPfx),
					}
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.VrfBgpBind(context.Background(),
						connect.NewRequest(&v1.VrfBgpBindRequest{Bindings: []*v1.VrfBgpBinding{b}}))
					if err != nil {
						return err
					}
					return printOperationResult(resp.Msg.Bound, resp.Msg.Errors, "VrfBgpBinding", "bound")
				},
			},
			{
				Name:  "unbind",
				Usage: "Remove a VRF's BGP binding",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "vrf", Required: true},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.VrfBgpUnbind(context.Background(),
						connect.NewRequest(&v1.VrfBgpUnbindRequest{VrfNames: []string{c.String("vrf")}}))
					if err != nil {
						return err
					}
					for _, e := range resp.Msg.Errors {
						fmt.Printf("error: %s: %s\n", e.TriggerPrefix, e.Reason)
					}
					if len(resp.Msg.UnboundVrfNames) > 0 {
						fmt.Printf("Unbound: %s\n", strings.Join(resp.Msg.UnboundVrfNames, ", "))
					}
					if len(resp.Msg.Errors) > 0 {
						return fmt.Errorf("%d unbind operation(s) failed", len(resp.Msg.Errors))
					}
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List VRF BGP bindings",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.VrfBgp.VrfBgpList(context.Background(),
						connect.NewRequest(&v1.VrfBgpListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Bindings)
					}
					headers := []string{"VRF", "RD", "IMPORT_RTS", "EXPORT_RTS", "REDISTRIBUTE", "MAX_PFX", "DEFAULT_LOCATOR"}
					var rows [][]string
					for _, b := range resp.Msg.Bindings {
						rows = append(rows, []string{
							b.VrfName,
							b.Rd,
							strings.Join(b.ImportRts, ","),
							strings.Join(b.ExportRts, ","),
							strings.Join(b.Redistribute, ","),
							fmt.Sprintf("%d", b.MaxPrefixes),
							b.DefaultLocator,
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}

// csvFlag splits a comma-separated CLI flag into a slice, trimming each
// element and dropping empties, returning nil for an empty flag.
func csvFlag(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
