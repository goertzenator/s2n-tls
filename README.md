# s2n-tls

High-level Haskell bindings to [s2n-tls](https://github.com/aws/s2n-tls), Amazon's TLS implementation.

## Overview

This package provides safe, idiomatic Haskell bindings to the s2n-tls library with:

- **Automatic memory management** using `ForeignPtr` for all opaque types
- **Haskell-idiomatic error handling** with exceptions for truly exceptional errors and `Either` for expected conditions like non-blocking I/O
- **MonadIO polymorphism** for flexible integration with your application's monad stack

## Installation

This package requires the s2n-tls C library to be installed on your system.

```bash
cabal build
```

## Quick Start

```haskell
import S2nTls

main :: IO ()
main = withS2nTls Linked $ \tls -> do
    -- Create a configuration
    config <- newConfig tls
    loadSystemCerts tls config
    setCipherPreferences tls config "default_tls13"

    -- Create a client connection
    conn <- newConnection tls Client
    setConnectionConfig tls conn config
    setServerName tls conn "example.com"
    setFd tls conn socketFd

    -- Perform handshake (loop until complete)
    let handshake = do
            result <- negotiate tls conn
            case result of
                Right () -> pure ()
                Left BlockedOnRead -> waitForRead >> handshake
                Left BlockedOnWrite -> waitForWrite >> handshake
                Left _ -> error "Unexpected block"
    handshake

    -- Send and receive data
    send tls conn "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    response <- recv tls conn 4096
    -- ...
```

## Modules

- **S2nTls** - Main module with `withS2nTls` and the `S2nTls` API record
- **S2nTls.Error** - Error types and exception handling
- **S2nTls.Types** - Safe `ForeignPtr` type aliases and enumerations
- **S2nTls.Config** - TLS configuration management
- **S2nTls.Connection** - TLS connection operations

## Error Handling

The library distinguishes between:

1. **Exceptions** (`S2nError`) - Thrown for truly exceptional conditions:
   - Internal library errors
   - Protocol violations
   - API usage errors

2. **Either values** - Returned for expected conditions:
   - `Left BlockedOnRead` - Operation would block waiting for data
   - `Left BlockedOnWrite` - Operation would block waiting to write
   - `Right result` - Operation completed successfully

## Dependencies

- [s2n-tls-ffi](https://hackage.haskell.org/package/s2n-tls-ffi) - Low-level FFI bindings
- [unliftio](https://hackage.haskell.org/package/unliftio) - For `MonadIO` and `MonadUnliftIO`

## License

BSD-3-Clause
