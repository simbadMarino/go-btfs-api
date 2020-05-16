module github.com/TRON-US/go-btfs-api

require (
	github.com/TRON-US/go-btfs-config v0.4.1
	github.com/TRON-US/go-btfs-files v0.2.0
	github.com/cheekybits/is v0.0.0-20150225183255-68e9c0620927
	github.com/gogo/protobuf v1.3.1
	github.com/ipfs/go-ipfs-util v0.0.1
	github.com/libp2p/go-libp2p-core v0.5.3
	github.com/libp2p/go-libp2p-metrics v0.1.0
	github.com/libp2p/go-libp2p-peer v0.2.0
	github.com/mitchellh/go-homedir v1.1.0
	github.com/multiformats/go-multiaddr v0.2.1
	github.com/multiformats/go-multiaddr-dns v0.2.0 // indirect
	github.com/multiformats/go-multiaddr-net v0.1.2
	github.com/tron-us/go-btfs-common v0.3.7
	github.com/tron-us/go-common/v2 v2.0.5
	github.com/whyrusleeping/tar-utils v0.0.0-20180509141711-8c6c8ba81d5c
)

go 1.13

replace github.com/libp2p/go-libp2p-core => github.com/TRON-US/go-libp2p-core v0.5.0
