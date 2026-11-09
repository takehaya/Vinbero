package cli

import (
	"context"
	"fmt"
	"strconv"

	"connectrpc.com/connect"
	"github.com/urfave/cli/v2"

	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
)

func deviceCommand() *cli.Command {
	return &cli.Command{
		Name:  "device",
		Usage: "Attach network interfaces to the data plane at runtime",
		Subcommands: []*cli.Command{
			{
				Name:  "attach",
				Usage: "Attach the XDP and TC programs to an interface (kept across daemon restarts)",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Interface name"},
					&cli.StringFlag{Name: "mode", Usage: "XDP mode: driver | generic | offload (default: internal.bpf.device_mode)"},
				},
				Action: func(c *cli.Context) error {
					resp, err := clientsFromContext(c).Device.DeviceAttach(context.Background(),
						connect.NewRequest(&v1.DeviceAttachRequest{Name: c.String("name"), Mode: c.String("mode")}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg)
					}
					d := resp.Msg.GetDevice()
					fmt.Printf("device %s attached (ifindex=%d mode=%s)\n", d.GetName(), d.GetIfindex(), d.GetMode())
					return nil
				},
			},
			{
				Name:  "detach",
				Usage: "Detach the programs from an interface attached with 'device attach'",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "name", Required: true, Usage: "Interface name"},
				},
				Action: func(c *cli.Context) error {
					name := c.String("name")
					if _, err := clientsFromContext(c).Device.DeviceDetach(context.Background(),
						connect.NewRequest(&v1.DeviceDetachRequest{Name: name})); err != nil {
						return err
					}
					fmt.Printf("device %s detached\n", name)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List the interfaces the data plane is attached to",
				Action: func(c *cli.Context) error {
					resp, err := clientsFromContext(c).Device.DeviceList(context.Background(),
						connect.NewRequest(&v1.DeviceListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg)
					}
					var rows [][]string
					for _, d := range resp.Msg.GetDevices() {
						source := "api"
						if d.GetConfig() {
							source = "config"
						}
						rows = append(rows, []string{d.GetName(), strconv.FormatUint(uint64(d.GetIfindex()), 10), d.GetMode(), source})
					}
					printTable([]string{"NAME", "IFINDEX", "MODE", "SOURCE"}, rows)
					return nil
				},
			},
		},
	}
}
