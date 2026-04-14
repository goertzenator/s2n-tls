# s2n-tls

High-level Haskell bindings to [s2n-tls](https://github.com/aws/s2n-tls), Amazon's TLS implementation.

## Overview

This package provides safe, idiomatic Haskell bindings to the s2n-tls library with:

- **Automatic memory management** using `ForeignPtr` for all opaque types
- **Haskell-idiomatic error handling** with exceptions for truly exceptional errors and `Either` for expected conditions like non-blocking I/O

## Installation

This package requires the s2n-tls C library to be installed on your system.

```bash
cabal build
```

## Quick Start

```haskell
{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

import Control.Exception (bracket)
import Network.Socket qualified as Net
import S2nTls

main :: IO ()
main = withS2nTls Linked $ \tls -> do
    config <- tls.newConfig
    tls.loadSystemCerts config
    tls.setCipherPreferences config "default_tls13"

    bracket (connectToServer "example.com" 443) Net.close $ \sock -> do
        conn <- tls.newConnection Client
        tls.setConnectionConfig conn config
        tls.setServerName conn "example.com"
        tls.setSocket conn sock

        tls.blockingNegotiate conn
        tls.blockingSendAll conn "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        response <- tls.blockingRecv conn 4096
        print response
```

## Documentation

See the **[Haddock documentation](https://hackage.haskell.org/package/s2n-tls)** for:

- Complete client and server examples
- Session ticket configuration and resumption
- Memory locking (mlock) limits and workarounds
- Error handling patterns

## Running Tests

Tests may exhaust the default mlock limit. Use:

```bash
S2N_DONT_MLOCK=1 cabal test
```

See the [mlock documentation](https://hackage.haskell.org/package/s2n-tls/docs/S2nTls.html#g:7) for details.

## License

Apache-2.0
