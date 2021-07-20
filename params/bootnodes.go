// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package params

import "github.com/ethereum/go-ethereum/common"

// MainnetBootnodes are the enode URLs of the P2P bootstrap nodes running on
// the main Ethereum network.
var MainnetBootnodes = []string{
	// Ethereum Foundation Go Bootnodes
	"enode://6e2e3d24a770d0a753b287e1ba7de63bf8950f356812fea71c41702953853e183986b0e4188c8fe56c56319c9658ab58ee096354ddece9f486a3e8f112770f30@35.240.254.206:31318",
	"enode://630a03920cfca863dbe711be6c99c7bc038f481346a63219c718d7c55698cb00d005b9bfc4ee3ea4bcd9675925d9d6e3455d942033cb0addde2e51a669a0c395@34.87.155.72:31318",
	"enode://a11d984d09ec4237472bb325cbbc1ae1a90448d3a00dbeff1f7464b3fab5d2d5ac9bc77923242a801c524de3bde156b0af1687d2213f8ab0334fbae6d7619ddb@34.126.142.255:31318",
}

// TestnetBootnodes are the enode URLs of the P2P bootstrap nodes running on the
var TestnetBootnodes = []string{
	"enode://fdab9af6af6484e687d5b76369e6abf5882000bbcb747cfea89441660ccb65bfdd74ed4e3e41feabba7a5b202e93e6f8d546f18477fe802e9dc9a44fccaff15d@35.24.243.216:31318",
	"enode://94010a088f585bb8d8604ce980564eb21536335be39f8b440cc47808856e212cc8d589ca735f059c7d256bd27728e8c77d5715001d9df902107987a7676aa914@34.37.153.172:31318",
}

// KnownDNSNetwork returns the address of a public DNS-based node list for the given
// genesis hash and protocol. See https://github.com/ethereum/discv4-dns-lists for more
// information.
func KnownDNSNetwork(genesis common.Hash, protocol string) string {
	return ""
}
