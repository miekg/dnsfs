# DNSFS

A DNS filesystem.

* Lowercase names are labels in the DNS.
* Names starting with an upper case are types: Txt, Soa, Srv, etc. The content is the string
  notation of the type's data.

Because the DNS is a not database, not a whole lot is visible, you have to try it out.

If a type for a name does not exist the file's contents is empty.

sticky bit is for DNSSEC signed names (there is an RRSIG returns in the reply).

By default shows Soa and Ns files. (r--r-----) perms

* ttls? no one cares ttl in access time



## Build

Build with: `go build -o dnsfsmain`.

## Also See

[An older attempt using Perl](https://miek.nl/2010/december/04/a-dns-filesystem/).
