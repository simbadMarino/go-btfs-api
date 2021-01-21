module github.com/TRON-US/go-btfs-api

require (
	github.com/TRON-US/go-btfs-config v0.6.0
	github.com/TRON-US/go-btfs-files v0.2.0
	github.com/cheekybits/is v0.0.0-20150225183255-68e9c0620927
	github.com/gogo/protobuf v1.3.1
	github.com/ipfs/go-ipfs-util v0.0.2
	github.com/libp2p/go-libp2p-core v0.6.1
	github.com/mitchellh/go-homedir v1.1.0
	github.com/multiformats/go-multiaddr v0.3.0
	github.com/multiformats/go-multiaddr-net v0.2.0
	github.com/tron-us/go-btfs-common v0.7.10
	github.com/tron-us/go-common/v2 v2.3.0
	github.com/whyrusleeping/tar-utils v0.0.0-20180509141711-8c6c8ba81d5c
)

go 1.13

replace github.com/libp2p/go-libp2p-core => github.com/TRON-US/go-libp2p-core v0.7.1
