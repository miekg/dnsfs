# DNSFS

A read-only DNS filesystem. Browse the DNS using the tools you know!

Because the DNS is a not database, dnsfs can't just display directories full of content. To help a
little bit it will query some set of qtypes to see if they exist. No subdomain (directories) will be
listed by default. The types queried by default are: SOA, NS, MX, DNSKEY, TXT, A and AAAA.

For subdomains and other types to exist they have to be queried, to see if they are defined in the
DNS.

CNAMEs are detected and made into symlinks.

## Structure

Each label is a new directory - regardless if the name is delegated or not. Accessed names are
cached.

* Lowercase names are *labels* in the DNS.
* Names starting with an upper case are types: A, Txt, Soa, Srv, etc. The content is the string
  notation of the type's data for the directory where the file lives.
* Permission are set to 'rw-rw-rw-' for non DNSSEC names as these are effectively writeable. For
  names that also have RRSIGs it's set to 'r--r--r--'.
* The TTL is not used and set to 3600 for all records.
* Inode are fixed: 1 for directories, 2 for files.
* Directory size is 4096.
* Link count is set to 1.

## Build

Build with: `go build -o dnsfsmain`. Or use the Makefile and just `make`.

## Usage

Start the dnsfs browser:

~~~ sh
% mkdir /tmp/dns
% ./dnsfsmain /tmp/dns
~~~

And then in a different terminal:

~~~ sh
% cd /tmp/dns
% ls
Dnskey  Ns  Soa
% cat Soa
.	63841	IN	SOA	a.root-servers.net. nstld.verisign-grs.com. 2019081000 1800 900 604800 86400
% ls
Soa
% cd blaat
cd: no such file or directory: blaat
% cd nl
% cd miek
% cd a
% cat A
a.miek.nl.	899	IN	A	176.58.119.54
~~~

To quit kill `dnsfsmain` with control-C and `fusermount -u /tmp/dns` to clean up.

See [this recording](https://asciinema.org/a/cphAcSWynSxuyGGiEhn9za8On).

## Also See

[An older attempt using Perl](https://miek.nl/2010/december/04/a-dns-filesystem/).
