# DNSFS

A DNS filesystem. Browse the DNS using the tools you know!

Because the DNS is a not database, dnsfs can't just display directories full of content. For things
to be queried you have to access them, either by changing into directories or listing files'
contents.

## Structure

Each label is a new directory - regardless if the name is delegated or not. Accessed names are
cached.

* Lowercase names are *labels* from the DNS.
* Names starting with an upper case are types: A, Txt, Soa, Srv, etc. The content is the string
  notation of the type's data for the directory where the file lives.
* Permission are set to 'rw-rw-rw-' for non DNSSEC names as these are effectively writeable. For
  names that also have RRSIGs it's set to 'r--r--r--'.
* The TTL is substracted from the current time and set as the mtime.
* Inode are numbered consecutively.
* Directory size is 4096.
* Link count is set to 1.

## Build

Build with: `go build -o dnsfsmain`.

## Also See

[An older attempt using Perl](https://miek.nl/2010/december/04/a-dns-filesystem/).
