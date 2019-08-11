package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/miekg/dnsfs/dnsfs"
	"github.com/miekg/dnsfs/resolv"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

func usage() {
	fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "  %s MOUNTPOINT\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		usage()
		os.Exit(2)
	}

	c, err := fuse.Mount(flag.Arg(0), fuse.FSName("dns"), fuse.Subtype("dnsfs"), fuse.LocalVolume(), fuse.ReadOnly())
	if err != nil {
		log.Fatal(err)
	}
	defer c.Close()

	log.Printf("Mounted dnsfs on: %s", flag.Arg(0))
	defer log.Printf("Unmounted dnsfs from: %s", flag.Arg(0))
	dfs := dnsfs.New(resolv.New())
	err = fs.Serve(c, dfs)
	if err != nil {
		log.Fatal(err)
	}

	<-c.Ready
	if err := c.MountError; err != nil {
		log.Fatal(err)
	}
	if err := fuse.Unmount(flag.Arg(0)); err != nil {
		log.Fatal(err)
	}
}
