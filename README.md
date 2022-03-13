# Encaya: REST and AIA API for Safe DANE Lookups

Encaya enables AIA-compatible TLS clients (e.g. CryptoAPI, Chromium, and Safari) to accept certificates specified by a safe subset of DANE (e.g. for Namecoin).

## Building

Prerequisites:

1. Ensure you have the Go tools installed.

2. If using Linux, ensure you have the `libcap` development headers
   installed. (Most distributions will have a package called `libcap-dev` or
   similar.)

Option A: Using Go build commands without Go modules (works on any platform with Bash; only Go 1.15-1.16.x; will not work on Go 1.17+):

1. Ensure you have the `GOPATH` environment variable set. (For those not
   familar with Go, setting it to the path to an empty directory will suffice.
   The directory will be filled with build files.)

2. Run `export GO111MODULE=off` to disable Go modules.

3. Run `go get -d -t -u github.com/namecoin/encaya/...`. The encaya source code will be
   retrieved automatically.

4. Run `go generate github.com/namecoin/x509-compressed/...`.  The compressed public key patch will be applied.

5. Run `go get -t -u github.com/namecoin/encaya/...`.  encaya will be built. The binaries will be at `$GOPATH/bin/encaya`.

Option B: Using Go build commands with Go modules (works on any platform with Bash; Go 1.15+:

1. Clone [x509-compressed](https://github.com/namecoin/x509-compressed) and encaya to sibling directories.

2. Install `x509-compressed` according to its "with Go modules" instructions.

3. Run the following in the encaya directory to set up Go modules:
   
   ~~~
   go mod init github.com/namecoin/encaya
   go mod edit -replace github.com/coreos/go-systemd=github.com/coreos/go-systemd/v22@latest -replace github.com/namecoin/x509-compressed=../x509-compressed
   go mod tidy
   ~~~

4. Run `go install ./...`.  encaya will be built. The binaries will be at `$GOPATH/bin/encaya`.

Option C: Using Makefile (non-Windows platforms):

1. Run `make`. The source repository will be retrieved via `go get`
   automatically.

Encaya can be run as a Windows service; see the output of `encaya --help`.

## Configuration

Encaya uses a configuration file which is looked for at `../etc/encaya.conf`
(relative to the executable path) and `/etc/encaya/encaya.conf`. You can override
this and all options on the command line.

## Suggested Setup

There are 3 machines involved in setup:

* DNS server.
    * Must have a trusted network path to a Namecoin client such as Namecoin Core.
* Encaya server.
    * Must have a trusted network path to the DNS server.
* Client.
    * No trusted network path is necessary, but any eavesdropper on the network path to the Encaya server will be able to see which Namecoin domain names you connect to (since AIA traffic is unencrypted).

In many cases, all 3 machines will be the same machine.  However, this is not a requirement.  For example, you might configure a mobile client to use servers that you set up on a desktop.  In fact, if the client is a TiVoized device such as an iOS device, you **must** set up the servers on a different machine, since TiVoized devices cannot install Encaya or ncdns.

Once you've decided which machine will play which role, follow these steps:

1. Install [ncdns](https://github.com/namecoin/ncdns) on the DNS server machine.
2. Configure `ncdns.conf` on the DNS server machine to point to the Encaya server machine for AIA.  The configured IP must be valid from the client machine's network perspective.
3. Start ncdns as a service on the DNS server machine.
4. Configure `encaya.conf` on the Encaya server machine to use ncdns's IP and port for DNS.
5. On the Encaya server machine, run `encayagen` to generate the Encaya root CA.
6. Start Encaya as a service on the Encaya server machine.
7. Copy `encaya.pem` to the client machine.  (If the client machine has a trusted network path to the Encaya server machine, you can download the certificate on the client machine by connecting to port 80 on the Encaya server machine in a web browser.  Otherwise, manually copy the file.)
8. Install `encaya.pem` on the client machine as a trusted root CA.  Setting EKU (TLS server authentication only) and name constraints (`bit` only) is recommended, e.g. via [certinject](https://github.com/namecoin/certinject).
9. Configure the client machine to use ncdns's IP and port as a stub zone for `bit.`.

## Theoretical background

See [Jeremy Rand's talk](https://www.namecoin.org/2021/01/01/namecoin-at-grayhat-2020-monero-village.html) at the Grayhat 2020 Monero Village.

## Warnings

Encaya does not protect you from MITM attacks by public CA's that are trusted by your TLS client.  You need another tool, such as [certinject](https://github.com/namecoin/certinject), for that.

## Licence

Copyright (C) 2018-2022 Namecoin Developers.

Encaya is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Encaya is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Encaya.  If not, see [https://www.gnu.org/licenses/](https://www.gnu.org/licenses/).
