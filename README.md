# enku

This is a simple CLI tool to encrypt data.

DON'T USE THIS PROGRAM

This is unaudited reimplemented crypto. I made this tool to have fun,
and it is not intended to actually be used.

# Building

This project uses `CMake`, and can be built with:

```txt
cmake --build build
```

which will place the `enku` binary in the `build` directory.

(You can use another directory besides `build` if you'd like)

# Usage

## Generating Keys

```txt
enku keygen .key.pem
```

## Encrypting data

```txt
enku encrypt .key.pem data.text > data.bin
```

This will print the binary data to standard out, so you can pipe
it or do whatever you want with it.

## Decrypting Data

```
enku decrypt .key.pem data.bin
```

This will write out the decoded data to standard out, so you can
pipe it to a file if you'd prefer.

## Implementation

This uses ChaCha20, as defined by [RFC 7539](https://tools.ietf.org/html/rfc7539).

The key file is encoded in a straightforward PEM format.

The output binary file includes the nonce, but currently, no form of authentication
is used, which is a major flaw in the scheme.
