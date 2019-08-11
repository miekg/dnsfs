package main

import (
	"os"
	"testing"

	"github.com/miekg/dnsfs/dnsfs"
	"github.com/miekg/dnsfs/resolv"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

// Todo use fstestutil

func testDnsFs(t *testing.T) {
	mountpoint := "/tmp/testdns"

	if err := os.Mkdir(mountpoint, 0755); err != nil {
		t.Fatal(err)
	}

	c, err := fuse.Mount(mountpoint, fuse.FSName("dns"), fuse.Subtype("testfs"), fuse.LocalVolume(), fuse.ReadOnly())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	t.Logf("Mounted dnsfs on: %s", mountpoint)
	dfs := dnsfs.New(resolv.T{})
	err = fs.Serve(c, dfs)
	if err != nil {
		t.Fatal(err)
	}

	<-c.Ready
	if err := c.MountError; err != nil {
		t.Fatal(err)
	}
}
