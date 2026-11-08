// Command vinbero-cni is the vinbero CNI plugin. The container runtime runs
// it with CNI_COMMAND set; see docs/design/ja/cni.md.
package main

import (
	"fmt"
	"os"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	cniversion "github.com/containernetworking/cni/pkg/version"

	"github.com/takehaya/vinbero/pkg/cni"
)

// version is set at build time (-X main.version), like vinbero and vinberod.
var version = "dev"

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "-v" || os.Args[1] == "--version") {
		fmt.Println("vinbero-cni", version)
		return
	}
	p := cni.NewPlugin()
	skel.PluginMainFuncs(skel.CNIFuncs{
		Add: func(args *skel.CmdArgs) error {
			res, err := p.Add(args)
			if err != nil {
				return err
			}
			conf, err := cni.ParseConf(args.StdinData)
			if err != nil {
				return err
			}
			return types.PrintResult(res, conf.CNIVersion)
		},
		Del:   p.Del,
		Check: p.Check,
	}, cniversion.PluginSupports("0.3.1", "0.4.0", "1.0.0"), "vinbero CNI plugin "+version)
}
