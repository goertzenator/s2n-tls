{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : S2nTls
Description : High-level Haskell bindings to s2n-tls
Copyright   : (c) 2026 Daniel Goertzen
License     : Apache-2.0
Maintainer  : daniel.goertzen@gmail.com
Stability   : experimental
Portability : non-portable (requires s2n-tls C library)

This module provides safe, high-level Haskell bindings to the
<https://github.com/aws/s2n-tls s2n-tls> library. It wraps the low-level
FFI bindings from "S2nTls.Ffi" with:

* Automatic memory management using 'ForeignPtr'
* Haskell-idiomatic error handling with exceptions and 'Either'
* Library initialization and cleanup via 'withS2nTls'

= Client Example

@
{\-# LANGUAGE OverloadedRecordDot #-\}
{\-# LANGUAGE OverloadedStrings #-\}

import Control.Exception (bracket)
import Network.Socket as Net
import S2nTls

main :: IO ()
main = withS2nTls Linked $ \\tls -> do
    -- Create a configuration
    config <- tls.newConfig
    tls.loadSystemCerts config
    tls.setCipherPreferences config "default_tls13"

    -- Connect to server
    bracket (connectToServer "example.com" 443) Net.close $ \\sock -> do
        -- Create a client connection
        conn <- tls.newConnection Client
        tls.setConnectionConfig conn config
        tls.setServerName conn "example.com"
        tls.setSocket conn sock

        -- Perform TLS handshake (blocking helper)
        tls.blockingNegotiate conn

        -- Send and receive data
        tls.blockingSendAll conn "GET \/ HTTP\/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
        response <- tls.blockingRecv conn 4096
        print response

connectToServer :: String -> Int -> IO Net.Socket
connectToServer host port = do
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    let hints = Net.defaultHints { Net.addrSocketType = Net.Stream }
    addr : _ <- Net.getAddrInfo (Just hints) (Just host) (Just (show port))
    Net.connect sock (Net.addrAddress addr)
    pure sock
@

= Server Example

@
{\-# LANGUAGE OverloadedRecordDot #-\}
{\-# LANGUAGE OverloadedStrings #-\}

import Control.Exception (bracket)
import Data.ByteString as BS
import Network.Socket as Net
import S2nTls

main :: IO ()
main = withS2nTls Linked $ \\tls -> do
    -- Load certificate and private key
    certPem <- BS.readFile "cert.pem"
    keyPem <- BS.readFile "key.pem"

    -- Create server configuration
    config <- tls.newConfig
    tls.setCipherPreferences config "default_tls13"
    certKey <- tls.loadCertChainAndKeyPem certPem keyPem
    tls.addCertChainAndKeyToStore config certKey

    -- Create server socket and listen
    bracket (createServerSocket 8443) Net.close $ \\serverSock -> do
        putStrLn "Server listening on port 8443..."

        -- Accept a connection
        (clientSock, _) <- Net.accept serverSock

        -- Create TLS connection for this client
        conn <- tls.newConnection Server
        tls.setConnectionConfig conn config
        tls.setSocket conn clientSock

        -- Perform TLS handshake
        tls.blockingNegotiate conn

        -- Receive and respond
        request <- tls.blockingRecv conn 4096
        putStrLn $ "Received: " \<\> show request
        tls.blockingSendAll conn "HTTP\/1.1 200 OK\\r\\n\\r\\nHello!"

        Net.close clientSock

createServerSocket :: Int -> IO Net.Socket
createServerSocket port = do
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.setSocketOption sock Net.ReuseAddr 1
    Net.bind sock (Net.SockAddrInet (fromIntegral port) (Net.tupleToHostAddress (0,0,0,0)))
    Net.listen sock 5
    pure sock
@

= Session Tickets

Session tickets allow TLS session resumption without server-side session storage.
The server encrypts session state into a \"ticket\" and sends it to the client, who
can present it on subsequent connections to skip the full handshake.

== Server-Side Setup

Servers must enable tickets and configure encryption keys:

@
import System.Entropy (getEntropy)

setupServerWithTickets :: S2nTls -> IO Config
setupServerWithTickets tls = do
    config <- tls.newConfig

    -- Enable session tickets
    tls.setSessionTicketsOnOff config True

    -- Add a ticket encryption key (32 random bytes)
    ticketKey <- getEntropy 32
    let keyName = "key-2024-01"  -- Unique name for key rotation
    tls.addTicketCryptoKey config keyName ticketKey Nothing

    -- Optional: configure key lifetimes
    tls.setTicketEncryptDecryptKeyLifetime config (2 * 60 * 60)  -- 2 hours
    tls.setTicketDecryptKeyLifetime config (13 * 60 * 60)        -- 13 hours

    pure config
@

__Key rotation__: You can call 'addTicketCryptoKey' even after the config is
assigned to connections. New connections will use the new key for encryption,
while old keys remain valid for decryption until their lifetime expires.

__Key lifetimes__:

* 'setTicketEncryptDecryptKeyLifetime': How long a key encrypts new tickets
* 'setTicketDecryptKeyLifetime': How long a key can decrypt old tickets after
  it stops encrypting (allows graceful rotation)

== Client-Side Setup

Clients register a callback to receive and store tickets:

@
import Data.IORef (IORef, newIORef, writeIORef)

setupClientWithTickets :: S2nTls -> IORef (Maybe BS.ByteString) -> IO Config
setupClientWithTickets tls ticketRef = do
    config <- tls.newConfig
    tls.loadSystemCerts config

    -- Enable session tickets
    tls.setSessionTicketsOnOff config True

    -- Register callback to store tickets
    tls.setSessionTicketCallback config $ \\ticketData lifetime -> do
        putStrLn $ "Received ticket, valid for " \<\> show lifetime \<\> " seconds"
        writeIORef ticketRef (Just ticketData)

    pure config
@

== Resuming a Session

On subsequent connections, the client presents the stored ticket:

@
resumeSession :: S2nTls -> Config -> Maybe BS.ByteString -> Net.Socket -> IO Connection
resumeSession tls config mTicket sock = do
    conn <- tls.newConnection Client
    tls.setConnectionConfig conn config
    tls.setServerName conn "example.com"

    -- Set the stored ticket for resumption
    case mTicket of
        Just ticket -> tls.setSession conn ticket
        Nothing -> pure ()

    tls.setSocket conn sock
    tls.blockingNegotiate conn

    -- Check if resumption succeeded
    resumed <- tls.isSessionResumed conn
    putStrLn $ if resumed then "Session resumed!" else "Full handshake"

    pure conn
@

= Memory Locking (mlock)

== What is mlock?

s2n-tls uses the Linux @mlock()@ system call to lock memory pages containing
cryptographic secrets (private keys, session keys, etc.) into RAM. This prevents
the operating system from swapping these pages to disk, where they could
potentially be recovered by an attacker after your application terminates.

== The RLIMIT_MEMLOCK Limit

Linux enforces a per-process limit on how much memory can be locked, controlled
by @RLIMIT_MEMLOCK@. On many systems, this defaults to just __64 KB__ (or even
32 KB on some Debian versions). Since s2n-tls locks memory for all TLS
connections and cryptographic operations, this limit can be exhausted quickly
in applications handling multiple connections.

When the limit is exceeded, you'll see errors like:

> Error Message: 'error calling mlock'
> Debug String: 'Error encountered in s2n_mem.c line 106'

== Solutions

__Option 1: Increase the mlock limit (recommended for production)__

Raise the limit for your shell session:

> ulimit -l unlimited

Or set it to a specific value (in KB):

> ulimit -l 65536  # 64 MB

For systemd services, add to your unit file:

> [Service]
> LimitMEMLOCK=infinity

For persistent user limits, add to @\/etc\/security\/limits.conf@:

> youruser  soft  memlock  unlimited
> youruser  hard  memlock  unlimited

__Option 2: Disable mlock (acceptable for development\/testing)__

Set the environment variable to disable memory locking entirely:

> S2N_DONT_MLOCK=1 ./your-application

== Security Considerations

* __With mlock enabled__: Secrets are protected from being written to swap,
  reducing the risk of recovery from disk. This is the recommended setting
  for production deployments handling sensitive data.

* __With mlock disabled__: Secrets may be swapped to disk under memory
  pressure. This is generally acceptable for development, testing, and
  applications where the threat model doesn't include disk forensics.

* __Note__: Even with mlock enabled, laptop suspend\/hibernate modes may
  save RAM contents to disk regardless of memory locks.

== Running Tests

Tests may exhaust the default mlock limit. Use:

> S2N_DONT_MLOCK=1 cabal test

= Error Handling

The library distinguishes between:

1. __Exceptions__ ('S2nError') - Thrown for truly exceptional conditions:

    * Internal library errors
    * Protocol violations
    * API usage errors

2. __Either values__ - Returned for expected conditions:

    * @Left 'BlockedOnRead'@ - Operation would block waiting for data
    * @Left 'BlockedOnWrite'@ - Operation would block waiting to write
    * @Right result@ - Operation completed successfully
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
    -- ^ Shutdown the TLS connection (bidirectional, non-blocking).
    , blockingShutdown :: Connection -> IO ()
    -- ^ Shutdown the TLS connection (bidirectional, blocking).
    , shutdownSend :: Connection -> IO (Either Blocked ())
    -- ^ Shutdown only the send side (non-blocking).
    , blockingShutdownSend :: Connection -> IO ()
    -- ^ Shutdown only the send side (blocking).
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
        , blockingShutdown = Conn.blockingShutdown ffi
        , shutdownSend = Conn.shutdownSend ffi
        , blockingShutdownSend = Conn.blockingShutdownSend ffi
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
