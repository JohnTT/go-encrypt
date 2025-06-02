# go-encrypt

[![Go Reference](https://pkg.go.dev/badge/github.com/JohnTT/go-encrypt/symmetric.svg)](https://pkg.go.dev/github.com/JohnTT/go-encrypt/symmetric)


A simple Go library for symmetric encryption and decryption using AES-GCM. This library provides an easy-to-use interface for encrypting and decrypting data with a passphrase-derived key, and supports JSON serialization of encrypted data.

## Features

- Symmetric encryption and decryption using AES-GCM
- Key derivation from passphrase using SHA-256
- JSON marshaling/unmarshaling of encrypted data with base64 encoding
- Simple API for integration

## Installation

```sh
go get github.com/JohnTT/go-encrypt/symmetric
```