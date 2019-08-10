package dnsfs

import (
	"bytes"
	"context"
	"os"
	"strings"

	"github.com/miekg/dnsfs/dnsutil"
	"github.com/miekg/dnsfs/resolv"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/miekg/dns"
)

var inode uint64 = 3

func New() FS {
	return FS{r: resolv.New()}
}

type FS struct {
	r resolv.R
}

func (f FS) Root() (fs.Node, error) {
	return &Dir{r: f.r, zone: ".", entries: []fuse.Dirent{}}, nil
}

type Dir struct {
	r       resolv.R
	zone    string
	entries []fuse.Dirent
	inode   uint64
}

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = d.inode
	a.Mode = os.ModeDir | 0555
	a.Size = 4096
	return nil
}

func (d *Dir) Lookup(ctx context.Context, name string) (fs.Node, error) {
	// If it starts with an upper case it's a request for a type for d.Name, which are files
	if strings.ToUpper(name[:1]) == string(name[0]) {
		qtype, ok := dns.StringToType[strings.ToUpper(name)]
		if !ok {
			return nil, fuse.ENOENT
		}

		f := &File{r: d.r, qtype: qtype, zone: d.zone}
		rrs, info, err := f.r.Do(f.zone, f.qtype)
		if err != nil {
			return nil, err
		}
		if !info.Exists {
			return nil, fuse.ENOENT
		}

		f.dnssec = info.Dnssec
		f.rrs = rrs
		f.inode = inode
		d.entries = append(d.entries, fuse.Dirent{Inode: inode, Name: name, Type: fuse.DT_Dir})
		inode++

		return f, nil
	}
	// Directories
	d1 := &Dir{r: d.r, zone: dnsutil.Join(dns.Fqdn(name), d.zone)}
	_, info, err := d1.r.Do(d1.zone, dns.TypeSOA)
	if err != nil {
		return nil, err
	}
	if !info.Exists {
		return nil, fuse.ENOENT
	}

	d.inode = inode
	d.entries = append(d.entries, fuse.Dirent{Inode: 1, Name: name, Type: fuse.DT_Dir})
	inode++
	return d1, nil
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) { return d.entries, nil }

type File struct {
	r     resolv.R
	zone  string
	qtype uint16
	inode uint64

	dnssec bool
	rrs    []dns.RR
}

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = f.inode
	a.Mode = 0666
	if f.dnssec {
		a.Mode = 0444
	}
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
		rrs, info, err := f.r.Do(f.zone, f.qtype)
		if err != nil {
			return err
		}
		f.dnssec = info.Dnssec
		f.rrs = rrs
	}
	// Check TTL and relookup
	return nil
}
