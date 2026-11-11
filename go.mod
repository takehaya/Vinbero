module github.com/takehaya/vinbero

go 1.25.5

require (
	connectrpc.com/connect v1.18.1
	github.com/cilium/ebpf v0.20.0
	github.com/containernetworking/cni v1.3.0
	github.com/google/gopacket v1.1.19
	github.com/google/uuid v1.6.0
	github.com/mcuadros/go-defaults v1.2.0
	github.com/osrg/gobgp/v4 v4.11.0
	github.com/pkg/errors v0.9.1
	github.com/tetratelabs/wazero v1.12.0
	github.com/urfave/cli/v2 v2.27.7
	github.com/vishvananda/netlink v1.3.1
	github.com/vishvananda/netns v0.0.5
	go.uber.org/zap v1.27.1
	golang.org/x/net v0.58.0
	golang.org/x/sys v0.47.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.11
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/dgryski/go-farm v0.0.0-20240924180020-3414d57e47da // indirect
	github.com/eapache/channels v1.1.0 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/gaissmai/bart v0.26.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.4.0 // indirect
	github.com/k-sone/critbitgo v1.4.0 // indirect
	github.com/orcaman/concurrent-map/v2 v2.0.1 // indirect
	github.com/pelletier/go-toml/v2 v2.2.3 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.7.0 // indirect
	github.com/segmentio/fasthash v1.0.3 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.12.0 // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/spf13/pflag v1.0.6 // indirect
	github.com/spf13/viper v1.20.1 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	go.uber.org/multierr v1.10.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
)

// gobgp fork carries the draft-mpmz-bess-mup-safi-01 T1ST framing patch.
// Some peers only accept draft-01 framing (source-less T1ST routes must
// omit the trailing SourceAddressLength octet; -03 framing is still
// accepted on decode, and a received -03 route is sent on unchanged). The
// tag tracks the fork's mup-t1st-source-optional-v4.11.0 branch on top of
// the upstream v4.11.0 release. If the patch lands in upstream gobgp the
// replace directive can be dropped.
replace github.com/osrg/gobgp/v4 => github.com/takehaya/gobgp/v4 v4.0.0-20261111072819-9bc1c17ec7bf
