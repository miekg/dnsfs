# DNSFS

A read-only DNS filesystem. Browse the DNS using the tools you know!

Listing an empty directory will make DNSFS query a default set of qtypes. The types queried by
default are: SOA, NS, MX, DNSKEY, DS, TXT, A and AAAA.

Because the DNS is a not database, no subdomains are listed by default. For subdomains and other
types to exist they have to be queried. I.e. you have to change directory into a subdomain to get it
queried. CNAMEs are detected and made into symlinks.

Queries are executed the buffer size set to 4096B and the DO bit is true. Google Public DNS is used
to query against.

## Structure

Each label is a directory - regardless if the name is delegated or not. Accessed names are
cached, but the TTL is not used.

* The filesystem is not writeable.
* Lowercase names are *labels* in the DNS.
* Names starting with an upper case are types: A, Txt, Soa, Srv, etc. The content is the string
  notation of the type's data for the directory where the file lives.
* Permission are set to 'rw-rw-rw-' for non DNSSEC names as these are effectively writeable. For
  names that also have RRSIGs it's set to 'r--r--r--'.
* The TTL is not used and set to 3600 for all records.
* Inode are fixed: 1 for directories, 2 for files, 3 for symlinks.
* Directory size is 4096.
* Link count is set to 1.
* Uid/Gid are set to the current user.

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
Dnskey  Ns  Soa  # default queries turned up these types
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

## Bugs

No useful application for DNSFS exists. There are no tests.
