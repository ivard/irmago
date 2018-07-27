package irmaclient

import (
	"math/big"
	"crypto/rand"
	"io"
)

type deviceKey struct {
	Key *big.Int
}

func renewDeviceKey (kss *keyshareServer) {
	deltaBytes := new([128]byte)
	io.ReadFull(rand.Reader, deltaBytes[:])

	kss.deviceKey.Key = new(big.Int)
	kss.deviceKey.Key.SetBytes(deltaBytes[:])
}

