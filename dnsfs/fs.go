package dnsfs

import (
	"bytes"
	"context"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/miekg/dnsfs/dnsutil"
	"github.com/miekg/dnsfs/resolv"

	"bazil.org/fuse"
	"bazil.org/fuse/fs"
	"github.com/miekg/dns"
)

func New() FS {
	return FS{r: resolv.New()}
}

type FS struct {
	r resolv.R
}

func (f FS) Root() (fs.Node, error) {
	return &Dir{r: f.r, zone: ".", entries: make(map[string]fuse.Dirent)}, nil
}

type Dir struct {
	r       resolv.R
	zone    string
	entries map[string]fuse.Dirent
}

func (d *Dir) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 1
	a.Mode = os.ModeDir | 0555
	a.Size = 4096
	if user, err := user.Current(); err == nil {
		a.Uid = id(user.Uid)
		a.Gid = id(user.Gid)
	}
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
		rrs, info, err := f.r.Do(f.zone, f.qtype, fuse.DT_File)
		if err != nil {
			return nil, err
		}
		if !info.Exists {
			return nil, fuse.ENOENT
		}

		f.dnssec = info.Dnssec
		f.rrs = rrs
		d.entries[name] = fuse.Dirent{Inode: 2, Name: name, Type: fuse.DT_File}

		return f, nil
	}
	// Directories
	d1 := &Dir{r: d.r, zone: dnsutil.Join(dns.Fqdn(name), d.zone), entries: map[string]fuse.Dirent{}}
	_, info, err := d1.r.Do(d1.zone, dns.TypeSOA, fuse.DT_Dir)
	if err != nil {
		return nil, err
	}
	if !info.Exists {
		return nil, fuse.ENOENT
	}

	d.entries[name] = fuse.Dirent{Inode: 1, Name: name, Type: fuse.DT_Dir}
	return d1, nil
}

func (d *Dir) ReadDirAll(ctx context.Context) ([]fuse.Dirent, error) {
	if len(d.entries) > 0 {
		return mapToSlice(d.entries), nil
	}

	for _, qtype := range []uint16{dns.TypeSOA, dns.TypeNS, dns.TypeMX, dns.TypeDNSKEY, dns.TypeTXT, dns.TypeA, dns.TypeAAAA} {
		f := &File{r: d.r, qtype: qtype, zone: d.zone}
		_, info, err := f.r.Do(f.zone, f.qtype, fuse.DT_File)
		if err != nil {
			continue
		}
		if !info.Exists {
			continue
		}
		switch qtype {
		case dns.TypeSOA:
			d.entries["Soa"] = fuse.Dirent{Inode: 2, Name: "Soa", Type: fuse.DT_File}
		case dns.TypeNS:
			d.entries["Ns"] = fuse.Dirent{Inode: 2, Name: "Ns", Type: fuse.DT_File}
		case dns.TypeMX:
			d.entries["Mx"] = fuse.Dirent{Inode: 2, Name: "Mx", Type: fuse.DT_File}
		case dns.TypeDNSKEY:
			d.entries["Dnskey"] = fuse.Dirent{Inode: 2, Name: "Dnskey", Type: fuse.DT_File}
		case dns.TypeTXT:
			d.entries["Txt"] = fuse.Dirent{Inode: 2, Name: "Txt", Type: fuse.DT_File}
		case dns.TypeA:
			d.entries["A"] = fuse.Dirent{Inode: 2, Name: "A", Type: fuse.DT_File}
		case dns.TypeAAAA:
			d.entries["Aaaa"] = fuse.Dirent{Inode: 2, Name: "Aaaa", Type: fuse.DT_File}
		}
	}

	return mapToSlice(d.entries), nil
}

type File struct {
	r     resolv.R
	zone  string
	qtype uint16

	dnssec bool
	rrs    []dns.RR
}

func (f *File) Attr(ctx context.Context, a *fuse.Attr) error {
	a.Inode = 2
	a.Mode = 0666
	if user, err := user.Current(); err == nil {
		a.Uid = id(user.Uid)
		a.Gid = id(user.Gid)
	}
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
		rrs, info, err := f.r.Do(f.zone, f.qtype, fuse.DT_File)
		if err != nil {
			return err
		}
		f.dnssec = info.Dnssec
		f.rrs = rrs
	}
	// Check TTL and relookup?
	return nil
}

func id(s string) uint32 {
	x, _ := strconv.Atoi(s)
	return uint32(x)
}

func mapToSlice(m map[string]fuse.Dirent) []fuse.Dirent {
	df := make([]fuse.Dirent, len(m))
	i := 0
	for _, dir := range m {
		df[i] = dir
		i++
	}
	return df
}
