package cli

import (
	"context"
	"fmt"
	"time"

	"connectrpc.com/connect"
	v1 "github.com/takehaya/vinbero/api/vinbero/v1"
	"github.com/urfave/cli/v2"
	"golang.org/x/sys/unix"
)

func fdbCommand() *cli.Command {
	return &cli.Command{
		Name:  "fdb",
		Usage: "Manage FDB (MAC address table) entries",
		Subcommands: []*cli.Command{
			{
				Name:  "create",
				Usage: "Create a static FDB entry",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "bd-id", Required: true, Usage: "Bridge Domain ID"},
					&cli.StringFlag{Name: "mac", Required: true, Usage: "MAC address (e.g., aa:bb:cc:dd:ee:ff)"},
					&cli.UintFlag{Name: "oif", Required: true, Usage: "Output interface index"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					_, err := clients.Fdb.FdbCreate(context.Background(),
						connect.NewRequest(&v1.FdbCreateRequest{
							BdId: uint32(c.Uint("bd-id")),
							Mac:  c.String("mac"),
							Oif:  uint32(c.Uint("oif")),
						}))
					if err != nil {
						return err
					}
					fmt.Println("Static FDB entry created.")
					return nil
				},
			},
			{
				Name:  "delete",
				Usage: "Delete an FDB entry",
				Flags: []cli.Flag{
					&cli.UintFlag{Name: "bd-id", Required: true, Usage: "Bridge Domain ID"},
					&cli.StringFlag{Name: "mac", Required: true, Usage: "MAC address"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					_, err := clients.Fdb.FdbDelete(context.Background(),
						connect.NewRequest(&v1.FdbDeleteRequest{
							BdId: uint32(c.Uint("bd-id")),
							Mac:  c.String("mac"),
						}))
					if err != nil {
						return err
					}
					fmt.Println("FDB entry deleted.")
					return nil
				},
			},
			{
				Name:  "flush",
				Usage: "Delete FDB entries (requires --yes)",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "yes", Required: true, Usage: "Confirm the destructive operation"},
					&cli.UintFlag{Name: "bd-id", Usage: "Only flush this BD (default: all BDs)"},
					&cli.BoolFlag{Name: "keep-static", Usage: "Preserve user-configured static entries"},
				},
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Fdb.FdbFlush(context.Background(),
						connect.NewRequest(&v1.FdbFlushRequest{
							BdId:       uint32(c.Uint("bd-id")),
							KeepStatic: c.Bool("keep-static"),
						}))
					if err != nil {
						return err
					}
					fmt.Printf("Flushed %d FDB entries\n", resp.Msg.DeletedCount)
					return nil
				},
			},
			{
				Name:  "list",
				Usage: "List all FDB entries",
				Action: func(c *cli.Context) error {
					clients := clientsFromContext(c)
					resp, err := clients.Fdb.FdbList(context.Background(),
						connect.NewRequest(&v1.FdbListRequest{}))
					if err != nil {
						return err
					}
					if useJSON(c) {
						return printJSON(resp.Msg.Entries)
					}
					headers := []string{"BD_ID", "MAC", "OIF", "TYPE", "AGE"}
					var rows [][]string
					for _, e := range resp.Msg.Entries {
						entryType := "dynamic"
						if e.IsStatic {
							entryType = "static"
						} else if e.IsRemote {
							entryType = "remote"
						}

						age := "-"
						if !e.IsStatic && e.LastSeen > 0 {
							age = formatAge(e.LastSeen)
						}

						rows = append(rows, []string{
							fmt.Sprintf("%d", e.BdId),
							e.Mac,
							fmt.Sprintf("%d", e.Oif),
							entryType,
							age,
						})
					}
					printTable(headers, rows)
					return nil
				},
			},
		},
	}
}

func formatAge(lastSeenNs uint64) string {
	var ts unix.Timespec
	_ = unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts)
	nowNs := uint64(ts.Sec)*1e9 + uint64(ts.Nsec)

	if lastSeenNs > nowNs {
		return "0s"
	}
	age := time.Duration(nowNs-lastSeenNs) * time.Nanosecond
	if age < time.Second {
		return "0s"
	}
	if age < time.Minute {
		return fmt.Sprintf("%ds", int(age.Seconds()))
	}
	if age < time.Hour {
		return fmt.Sprintf("%dm%ds", int(age.Minutes()), int(age.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm", int(age.Hours()), int(age.Minutes())%60)
}
