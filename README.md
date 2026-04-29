# s2n-tls

High-level Haskell bindings to [s2n-tls](https://github.com/aws/s2n-tls), Amazon's TLS implementation.

## Overview

This package provides safe, idiomatic Haskell bindings to the s2n-tls library with:

- **Automatic memory management** using `ForeignPtr` for all opaque types
- **Haskell-idiomatic error handling** with exceptions for truly exceptional errors and `Either` for expected conditions like non-blocking I/O

## Quick Start

```haskell
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

import Control.Exception (bracket)
import Network.Socket
import S2nTls

main :: IO ()
main = withS2nTls Linked $ \tls -> do
    config <- tls.newConfig
    tls.setCipherPreferences config "default_tls13"

    bracket (connectToServer "example.com" 443) close $ \sock -> do
        conn <- tls.newConnection Client
        tls.setConnectionConfig conn config
        tls.setServerName conn "example.com"
        tls.setSocket conn sock

        tls.blockingNegotiate conn
        tls.blockingSendAll conn "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        response <- tls.blockingRecv conn 4096
        print response
```

## Running Tests

Tests may exhaust the default mlock limit. Use:

```bash
S2N_DONT_MLOCK=1 cabal test
```

See the mlock section in the Haddock documentation for details on memory locking.

## Related Packages

- [s2n-tls-ffi](https://github.com/goertzenator/s2n-tls-ffi) - Low-level FFI bindings (used internally by this package)
- [warp-s2n-tls](https://github.com/goertzenator/warp-s2n-tls) - TLS support for Warp using s2n-tls

## License

Apache-2.0
