{-# LANGUAGE PatternSynonyms #-}

-- |
-- Module      : S2nTls
-- Description : High-level Haskell bindings to s2n-tls
-- Copyright   : (c) 2026 Daniel Goertzen
-- License     : Apache-2.0
-- Maintainer  : daniel.goertzen@gmail.com
-- Stability   : experimental
-- Portability : non-portable (requires s2n-tls C library)
--
-- This module provides safe, high-level Haskell bindings to the s2n-tls library.
-- It wraps the low-level FFI bindings from "S2nTls.Ffi" with:
--
-- \* Automatic memory management using 'ForeignPtr'
-- \* Haskell-idiomatic error handling with exceptions and 'Either'
-- \* Library initialization and cleanup via 'withS2nTls'
--
-- = Basic Usage
--
-- @
-- import S2nTls
--
-- main :: IO ()
-- main = withS2nTls Linked $ \\tls -> do
--     -- Create a configuration
--     config <- newConfig tls
--     loadSystemCerts tls config
--     setCipherPreferences tls config "default_tls13"
--
--     -- Create a client connection
--     conn <- newConnection tls Client
--     setConnectionConfig tls conn config
--     setServerName tls conn "example.com"
--     setFd tls conn socketFd
--
--     -- Perform handshake (loop until complete)
--     let handshake = do
--             result <- negotiate tls conn
--             case result of
--                 Right () -> pure ()
--                 Left BlockedOnRead -> waitForRead >> handshake
--                 Left BlockedOnWrite -> waitForWrite >> handshake
--                 Left _ -> error "Unexpected block"
--     handshake
--
--     -- Send data
--     send tls conn "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
--
--     -- Receive data
--     response <- recv tls conn 4096
--     ...
-- @

{- |
Module      : S2nTls
Copyright   : (c) 2026
License     : BSD-3-Clause
Maintainer  : daniel.goertzen@gmail.com
-}
module S2nTls (
    -- * Library Initialization
    withS2nTls,

    -- * High-Level API Record
    S2nTls (..),

    -- * Types

    -- ** Safe Pointer Types
    Config,
    Connection,
    CertChainAndKey,

    -- ** Connection Mode
    Mode (..),
    pattern Server,
    pattern Client,

    -- ** TLS Versions
    TlsVersion (..),
    pattern SSLv2,
    pattern SSLv3,
    pattern TLS10,
    pattern TLS11,
    pattern TLS12,
    pattern TLS13,

    -- ** Certificate Authentication
    CertAuthType (..),
    pattern CertAuthNone,
    pattern CertAuthRequired,
    pattern CertAuthOptional,

    -- ** Blocked Status
    Blocked (..),

    -- * Errors
    S2nError (..),
    S2nErrorType (..),

    -- * Re-exports from s2n-tls-ffi
    Library (..),
) where

import Control.Exception (bracket, throwIO)
import Data.ByteString (ByteString)
import Data.Word (Word32, Word64)
import Foreign.C.Types (CInt)
import Network.Socket (Socket)
import S2nTls.Config qualified as Config
import S2nTls.Connection qualified as Conn
import S2nTls.Error
import S2nTls.Ffi (Library (..), withS2nTlsFfi)
import S2nTls.Ffi.Types (S2nTlsFfi (..))
import S2nTls.Types

{- | A record containing all high-level s2n-tls operations.
This record is provided by 'withS2nTls' and provides a convenient
way to access all TLS functionality.
-}
data S2nTls = S2nTls
    { newConfig :: IO Config
    -- ^ Create a new TLS configuration with default settings.
    , newConfigMinimal :: IO Config
    -- ^ Create a new minimal TLS configuration.
    , loadCertChainAndKeyPem ::
        -- \| Certificate chain PEM
        ByteString ->
        -- \| Private key PEM
        ByteString ->
        IO CertChainAndKey
    -- ^ Load a certificate chain and private key from PEM data.
    , addCertChainAndKeyToStore :: Config -> CertChainAndKey -> IO ()
    -- ^ Add a certificate chain and key to a configuration's store.
    , setVerificationCaLocation ::
        Config ->
        -- \| CA file path
        Maybe FilePath ->
        -- \| CA directory path
        Maybe FilePath ->
        IO ()
    -- ^ Set the CA certificate locations for verification.
    , addPemToTrustStore ::
        Config ->
        -- \| PEM-encoded certificate
        String ->
        IO ()
    -- ^ Add a PEM certificate to the trust store.
    , wipeTrustStore :: Config -> IO ()
    -- ^ Clear the trust store.
    , loadSystemCerts :: Config -> IO ()
    -- ^ Load system CA certificates into the trust store.
    , setCipherPreferences ::
        Config ->
        -- \| Security policy name
        String ->
        IO ()
    -- ^ Set cipher preferences using a security policy name.
    , setClientAuthType :: Config -> CertAuthType -> IO ()
    -- ^ Set client certificate authentication type.
    , disableX509Verification :: Config -> IO ()
    -- ^ Disable X.509 certificate verification (insecure!).
    , setProtocolPreferences ::
        Config ->
        -- \| List of protocol names
        [String] ->
        IO ()
    -- ^ Set application protocol preferences (ALPN).
    , newConnection :: Mode -> IO Connection
    -- ^ Create a new TLS connection.
    , setConnectionConfig :: Connection -> Config -> IO ()
    -- ^ Set the configuration for a connection.
    , setFd :: Connection -> CInt -> IO ()
    -- ^ Set both read and write file descriptors.
    , setReadFd :: Connection -> CInt -> IO ()
    -- ^ Set the read file descriptor.
    , setWriteFd :: Connection -> CInt -> IO ()
    -- ^ Set the write file descriptor.
    , setSocket :: Connection -> Socket -> IO ()
    -- ^ Set a socket, storing the reference and extracting the file descriptor.
    , setServerName :: Connection -> String -> IO ()
    -- ^ Set the server name for SNI.
    , getServerName :: Connection -> IO (Maybe String)
    -- ^ Get the server name from the connection.
    , negotiate :: Connection -> IO (Either Blocked ())
    -- ^ Perform the TLS handshake (non-blocking).
    , blockingNegotiate :: Connection -> IO ()
    -- ^ Perform the TLS handshake (blocking).
    , send :: Connection -> ByteString -> IO (Either Blocked Int)
    -- ^ Send data over the TLS connection (non-blocking).
    , blockingSend :: Connection -> ByteString -> IO Int
    -- ^ Send data over the TLS connection (blocking).
    , blockingSendAll :: Connection -> ByteString -> IO ()
    -- ^ Send all data over the TLS connection (blocking, loops until complete).
    , recv ::
        Connection ->
        -- \| Maximum bytes to receive
        Int ->
        IO (Either Blocked ByteString)
    -- ^ Receive data from the TLS connection (non-blocking).
    , blockingRecv ::
        Connection ->
        -- \| Maximum bytes to receive
        Int ->
        IO ByteString
    -- ^ Receive data from the TLS connection (blocking).
    , shutdown :: Connection -> IO (Either Blocked ())
    -- ^ Shutdown the TLS connection (bidirectional).
    , shutdownSend :: Connection -> IO (Either Blocked ())
    -- ^ Shutdown only the send side.
    , getApplicationProtocol :: Connection -> IO (Maybe String)
    -- ^ Get the negotiated application protocol (ALPN).
    , getActualProtocolVersion :: Connection -> IO TlsVersion
    -- ^ Get the actual negotiated TLS protocol version.
    , getCipher :: Connection -> IO String
    -- ^ Get the negotiated cipher suite name.
    , isSessionResumed :: Connection -> IO Bool
    -- ^ Check if this is a resumed session.
    , setSession :: Connection -> ByteString -> IO ()
    -- ^ Set session data for resumption (call before negotiate).
    , setSessionTicketsOnOff :: Config -> Bool -> IO ()
    -- ^ Enable or disable session tickets.
    , addTicketCryptoKey ::
        Config ->
        -- \| Key name
        ByteString ->
        -- \| Key data (32 random bytes)
        ByteString ->
        -- \| Introduction time (Nothing = now)
        Maybe Word64 ->
        IO ()
    -- ^ Add a session ticket encryption key. This is the only function that may
    -- safely mutate a Config after it has been assigned to a Connection.
    , setTicketDecryptKeyLifetime :: Config -> Word64 -> IO ()
    -- ^ Set decrypt-only key lifetime in seconds.
    , setTicketEncryptDecryptKeyLifetime :: Config -> Word64 -> IO ()
    -- ^ Set encrypt+decrypt key lifetime in seconds.
    , setSessionTicketCallback ::
        Config ->
        -- \| Callback receives ticket data and lifetime
        (ByteString -> Word32 -> IO ()) ->
        IO ()
    -- ^ Set callback to receive session tickets (client-side).
    , wipeConnection :: Connection -> IO ()
    -- ^ Wipe the connection for reuse.
    , freeHandshake :: Connection -> IO ()
    -- ^ Free handshake-related memory.
    , releaseBuffers :: Connection -> IO ()
    -- ^ Release all buffers.
    }

{- | Initialize the s2n-tls library and run an action with a high-level API.
This handles library loading, setup, and cleanup automatically.

The s2n-tls library must be initialized before any other s2n functions
are called, and cleaned up when done. This function ensures proper
initialization and cleanup.

Note: This function tolerates @S2N_ERR_INITIALIZED@ errors from @s2n_init()@,
since @s2n_cleanup()@ does not clear the internal initialization flag.
This allows multiple uses of @withS2nTls@ within the same process.

Example:

@
import S2nTls

main = withS2nTls Linked $ \\tls -> do
    config <- tls.newConfig
    -- ... use the TLS API ...
@
-}
withS2nTls :: Library -> (S2nTls -> IO a) -> IO a
withS2nTls lib action =
    withS2nTlsFfi lib $ \ffi ->
        bracket
            (initS2n ffi >> pure (mkS2nTls ffi))
            (\_ -> s2n_cleanup ffi)
            action

{- | Initialize s2n-tls, tolerating the "already initialized" error.
s2n_cleanup() doesn't clear the initialization flag, so subsequent
calls to s2n_init() will return an error. This is safe to ignore
since the library is already ready to use.

We check for usage/internal error types with "initialized" in the message
rather than specific error codes, since error codes are not ABI stable.
-}
initS2n :: S2nTlsFfi -> IO ()
initS2n ffi = do
    result <- s2n_init ffi
    case result of
        Right _ -> pure ()
        Left ffiErr -> do
            err <- fromFfiError ffi ffiErr
            case err of
                -- Accept "already initialized" errors.
                -- Match is bit janky, but we have no other way.  Detail error codes are not ABI-stable so we can't use them.
                S2nError{s2nErrorType = ErrorInternal, s2nErrorMessage = "s2n is initialized"} -> pure ()
                _ -> throwIO err

-- | Create the S2nTls record from the low-level FFI bindings.
mkS2nTls :: S2nTlsFfi -> S2nTls
mkS2nTls ffi =
    S2nTls
        { newConfig = Config.newConfig ffi
        , newConfigMinimal = Config.newConfigMinimal ffi
        , loadCertChainAndKeyPem = Config.loadCertChainAndKeyPem ffi
        , addCertChainAndKeyToStore = Config.addCertChainAndKeyToStore ffi
        , setVerificationCaLocation = Config.setVerificationCaLocation ffi
        , addPemToTrustStore = Config.addPemToTrustStore ffi
        , wipeTrustStore = Config.wipeTrustStore ffi
        , loadSystemCerts = Config.loadSystemCerts ffi
        , setCipherPreferences = Config.setCipherPreferences ffi
        , setClientAuthType = Config.setClientAuthType ffi
        , disableX509Verification = Config.disableX509Verification ffi
        , setProtocolPreferences = Config.setProtocolPreferences ffi
        , newConnection = Conn.newConnection ffi
        , setConnectionConfig = Conn.setConnectionConfig ffi
        , setFd = Conn.setFd ffi
        , setReadFd = Conn.setReadFd ffi
        , setWriteFd = Conn.setWriteFd ffi
        , setSocket = Conn.setSocket ffi
        , setServerName = Conn.setServerName ffi
        , getServerName = Conn.getServerName ffi
        , negotiate = Conn.negotiate ffi
        , blockingNegotiate = Conn.blockingNegotiate ffi
        , send = Conn.send ffi
        , blockingSend = Conn.blockingSend ffi
        , blockingSendAll = Conn.blockingSendAll ffi
        , recv = Conn.recv ffi
        , blockingRecv = Conn.blockingRecv ffi
        , shutdown = Conn.shutdown ffi
        , shutdownSend = Conn.shutdownSend ffi
        , getApplicationProtocol = Conn.getApplicationProtocol ffi
        , getActualProtocolVersion = Conn.getActualProtocolVersion ffi
        , getCipher = Conn.getCipher ffi
        , isSessionResumed = Conn.isSessionResumed ffi
        , setSession = Conn.setSession ffi
        , setSessionTicketsOnOff = Config.setSessionTicketsOnOff ffi
        , addTicketCryptoKey = Config.addTicketCryptoKey ffi
        , setTicketDecryptKeyLifetime = Config.setTicketDecryptKeyLifetime ffi
        , setTicketEncryptDecryptKeyLifetime = Config.setTicketEncryptDecryptKeyLifetime ffi
        , setSessionTicketCallback = Config.setSessionTicketCallback ffi
        , wipeConnection = Conn.wipeConnection ffi
        , freeHandshake = Conn.freeHandshake ffi
        , releaseBuffers = Conn.releaseBuffers ffi
        }
