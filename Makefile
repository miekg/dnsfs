all: dnsfsmain

dnsfsmain: *.go dnsfs/*.go resolv/*.go dnsutil/*.go
	go build -o dnsfsmain
