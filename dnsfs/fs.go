package dnsfs

import (
	"bytes"
	"context"
	"os"
	"strings"

	"github.com/miekg/dns"
	"github.com/miekg/dnsfs/resolv"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
)

func New() FS {
	return FS{r: resolv.New()}
}

type FS struct {
	r resolv.R
}

func (f FS) Root() (fs.Node, error) {
	return &Dir{r: f.r, name: "."}, nil
}

type Dir struct {
	r    resolv.R
	name string
}

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 1
	a.Mode = os.ModeDir | 0555
	return nil
}

func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	// if it starts with an upper case it's a request for a type for d.Name, which are files
	if strings.ToUpper(name[:1]) == string(name[0]) {
		qtype, ok := dns.StringToType[strings.ToUpper(name)]
		if !ok {
			return nil, fuse.ENOENT
		}

		f := &File{r: d.r, qtype: qtype, zone: d.name}
		rrs, rcode, dnssec, err := f.r.Do(f.zone, f.qtype)
		if err != nil {
			return nil, err
		}
		if rcode != dns.RcodeSuccess {
			return nil, fuse.ENOENT
		}
		if len(rrs) == 0 { // nodata
			return nil, fuse.ENOENT
		}

		f.dnssec = dnssec
		f.rrs = rrs

		return f, nil
	}

	// here we have directories

	return nil, fuse.ENOENT
}

var dirDirs = []fuse.Dirent{
	{Inode: 2, Name: "Soa", Type: fuse.DT_File},
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	return dirDirs, nil
}

type File struct {
	r     resolv.R
	zone  string
	qtype uint16

	dnssec bool
	rrs    []dns.RR
}

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	if err := f.Do(ctx); err != nil {
		return err
	}

	a.Inode = 2
	a.Mode = 0444
	for i := range f.rrs {
		a.Size += uint64(len(f.rrs[i].String())) + 1
	}
	return nil
}

func (f *File) ReadAll(ctx context.Context) ([]byte, error) {
	if err := f.Do(ctx); err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	for i := range f.rrs {
		buf.WriteString(f.rrs[i].String())
		buf.WriteString("\n")
	}
	return buf.Bytes(), nil
}

func (f *File) Do(ctx context.Context) error {
	if len(f.rrs) == 0 {
		rrs, _, dnssec, err := f.r.Do(f.zone, f.qtype)
		if err != nil {
			return err
		}
		f.dnssec = dnssec
		f.rrs = rrs
	}
	// Check TTL and relookup
	return nil
}
