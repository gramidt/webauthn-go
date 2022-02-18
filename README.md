WebAuthn Library
=============
[![GoDoc](https://godoc.org/github.com/teamhanko/webauthn-go?status.svg)](https://godoc.org/github.com/teamhanko/webauthn)
![Build Status](https://github.com/teamhanko/webauthn-go/workflows/Go/badge.svg)
[![Go Report Card](https://goreportcard.com/badge/github.com/teamhanko/webauthn-go)](https://goreportcard.com/report/github.com/teamhanko/webauthn)

This library, written in golang provides the ability to use webauthn/fido2. It is the core that powers the [Hanko Authentication API](https://docs.hanko.io/home)
and [Hanko Identity](https://docs.hanko.io/identity/home).
Apart from Basic functionality it offers:

* Support for Resident Keys
* Possibility to add a Policy which decides on which Authenticators are accepted when an Attestation is sent
* Apple Attestation support
* Meta Data Service v3

# Usage
TODO

# Acknowledgements
This repository was forked from the [duo-labs](https://github.com/duo-labs/webauthn) webauthn library.
We modified it to suit our needs and made some significant architectural cuts that made it incompatible with the upstream.