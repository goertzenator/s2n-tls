{-# LANGUAGE PatternSynonyms #-}

-- \|
-- Module      : S2nTls
-- Description : High-level Haskell bindings to s2n-tls
-- License     : BSD-3-Clause
--
-- This module provides safe, high-level Haskell bindings to the s2n-tls library.
-- It wraps the low-level FFI bindings from "S2nTls.Sys" with:
--
-- \* Automatic memory management using 'ForeignPtr'
-- \* Haskell-idiomatic error handling with exceptions and 'Either'
-- \* Library initialization and cleanup via 'withS2nTls'
--
-- = Basic Usage
--
-- @
-- import S2nTls
-- import S2nTls.Sys (getLinkedTlsSys)
--
-- main :: IO ()
-- main = withS2nTls getLinkedTlsSys $ \\tls -> do
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

    -- * Re-exports from s2n-tls-sys
    S2nTlsSys (..),
) where

import Control.Monad
import Data.ByteString (ByteString)
import Foreign.C.Types (CInt)
import S2nTls.Config qualified as Config
import S2nTls.Connection qualified as Conn
import S2nTls.Error (S2nError (..), S2nErrorType (..), fromSysEither)
import S2nTls.Sys.Types (S2nTlsSys (..))
import S2nTls.Types
import UnliftIO

{- | A record containing all high-level s2n-tls operations.
This record is provided by 'withS2nTls' and provides a convenient
way to access all TLS functionality.

The type parameter @m@ is the monad in which operations run (typically 'IO').
-}
data S2nTls m = S2nTls
    { newConfig :: m Config
    -- ^ Create a new TLS configuration with default settings.
    , newConfigMinimal :: m Config
    -- ^ Create a new minimal TLS configuration.
    , loadCertChainAndKeyPem ::
        -- | Certificate chain PEM
        ByteString ->
        -- | Private key PEM
        ByteString ->
        m CertChainAndKey
    -- ^ Load a certificate chain and private key from PEM data.
    , addCertChainAndKeyToStore :: Config -> CertChainAndKey -> m ()
    -- ^ Add a certificate chain and key to a configuration's store.
    , setVerificationCaLocation ::
        Config ->
        -- | CA file path
        Maybe FilePath ->
        -- | CA directory path
        Maybe FilePath ->
        m ()
    -- ^ Set the CA certificate locations for verification.
    , addPemToTrustStore ::
        Config ->
        -- | PEM-encoded certificate
        String ->
        m ()
    -- ^ Add a PEM certificate to the trust store.
    , wipeTrustStore :: Config -> m ()
    -- ^ Clear the trust store.
    , loadSystemCerts :: Config -> m ()
    -- ^ Load system CA certificates into the trust store.
    , setCipherPreferences ::
        Config ->
        -- | Security policy name
        String ->
        m ()
    -- ^ Set cipher preferences using a security policy name.
    , setClientAuthType :: Config -> CertAuthType -> m ()
    -- ^ Set client certificate authentication type.
    , disableX509Verification :: Config -> m ()
    -- ^ Disable X.509 certificate verification (insecure!).
    , setProtocolPreferences ::
        Config ->
        -- | List of protocol names
        [String] ->
        m ()
    -- ^ Set application protocol preferences (ALPN).
    , newConnection :: Mode -> m Connection
    -- ^ Create a new TLS connection.
    , setConnectionConfig :: Connection -> Config -> m ()
    -- ^ Set the configuration for a connection.
    , setFd :: Connection -> CInt -> m ()
    -- ^ Set both read and write file descriptors.
    , setReadFd :: Connection -> CInt -> m ()
    -- ^ Set the read file descriptor.
    , setWriteFd :: Connection -> CInt -> m ()
    -- ^ Set the write file descriptor.
    , setServerName :: Connection -> String -> m ()
    -- ^ Set the server name for SNI.
    , getServerName :: Connection -> m (Maybe String)
    -- ^ Get the server name from the connection.
    , negotiate :: Connection -> m (Either Blocked ())
    -- ^ Perform the TLS handshake (non-blocking).
    , blockingNegotiate :: Connection -> m ()
    -- ^ Perform the TLS handshake (blocking).
    , send :: Connection -> ByteString -> m (Either Blocked Int)
    -- ^ Send data over the TLS connection (non-blocking).
    , blockingSend :: Connection -> ByteString -> m Int
    -- ^ Send data over the TLS connection (blocking).
    , blockingSendAll :: Connection -> ByteString -> m ()
    -- ^ Send all data over the TLS connection (blocking, loops until complete).
    , recv ::
        Connection ->
        -- | Maximum bytes to receive
        Int ->
        m (Either Blocked ByteString)
    -- ^ Receive data from the TLS connection (non-blocking).
    , blockingRecv ::
        Connection ->
        -- | Maximum bytes to receive
        Int ->
        m ByteString
    -- ^ Receive data from the TLS connection (blocking).
    , shutdown :: Connection -> m (Either Blocked ())
    -- ^ Shutdown the TLS connection (bidirectional).
    , shutdownSend :: Connection -> m (Either Blocked ())
    -- ^ Shutdown only the send side.
    , getApplicationProtocol :: Connection -> m (Maybe String)
    -- ^ Get the negotiated application protocol (ALPN).
    , getActualProtocolVersion :: Connection -> m TlsVersion
    -- ^ Get the actual negotiated TLS protocol version.
    , getCipher :: Connection -> m String
    -- ^ Get the negotiated cipher suite name.
    , isSessionResumed :: Connection -> m Bool
    -- ^ Check if this is a resumed session.
    , wipeConnection :: Connection -> m ()
    -- ^ Wipe the connection for reuse.
    , freeHandshake :: Connection -> m ()
    -- ^ Free handshake-related memory.
    , releaseBuffers :: Connection -> m ()
    -- ^ Release all buffers.
    }

{- | Initialize the s2n-tls library and run an action with a high-level API.
This handles library setup and cleanup automatically.

The s2n-tls library must be initialized before any other s2n functions
are called, and cleaned up when done. This function ensures proper
initialization and cleanup.

Example:

@
import S2nTls
import S2nTls.Sys (getLinkedTlsSys)

main = withS2nTls getLinkedTlsSys $ \\tls -> do
    config <- tls.newConfig
    -- ... use the TLS API ...
@
-}
withS2nTls :: (MonadUnliftIO m) => S2nTlsSys -> (S2nTls m -> m a) -> m a
withS2nTls sys =
    bracket
        ( do
            -- Call s2n_init.
            void $ liftIO $ s2n_init sys >>= fromSysEither sys
            pure $ mkS2nTls sys
        )
        (\_ -> liftIO $ s2n_cleanup sys)

-- | Create the S2nTls record from the low-level sys bindings.
mkS2nTls :: (MonadIO m) => S2nTlsSys -> S2nTls m
mkS2nTls sys =
    S2nTls
        { newConfig = Config.newConfig sys
        , newConfigMinimal = Config.newConfigMinimal sys
        , loadCertChainAndKeyPem = Config.loadCertChainAndKeyPem sys
        , addCertChainAndKeyToStore = Config.addCertChainAndKeyToStore sys
        , setVerificationCaLocation = Config.setVerificationCaLocation sys
        , addPemToTrustStore = Config.addPemToTrustStore sys
        , wipeTrustStore = Config.wipeTrustStore sys
        , loadSystemCerts = Config.loadSystemCerts sys
        , setCipherPreferences = Config.setCipherPreferences sys
        , setClientAuthType = Config.setClientAuthType sys
        , disableX509Verification = Config.disableX509Verification sys
        , setProtocolPreferences = Config.setProtocolPreferences sys
        , newConnection = Conn.newConnection sys
        , setConnectionConfig = Conn.setConnectionConfig sys
        , setFd = Conn.setFd sys
        , setReadFd = Conn.setReadFd sys
        , setWriteFd = Conn.setWriteFd sys
        , setServerName = Conn.setServerName sys
        , getServerName = Conn.getServerName sys
        , negotiate = Conn.negotiate sys
        , blockingNegotiate = Conn.blockingNegotiate sys
        , send = Conn.send sys
        , blockingSend = Conn.blockingSend sys
        , blockingSendAll = Conn.blockingSendAll sys
        , recv = Conn.recv sys
        , blockingRecv = Conn.blockingRecv sys
        , shutdown = Conn.shutdown sys
        , shutdownSend = Conn.shutdownSend sys
        , getApplicationProtocol = Conn.getApplicationProtocol sys
        , getActualProtocolVersion = Conn.getActualProtocolVersion sys
        , getCipher = Conn.getCipher sys
        , isSessionResumed = Conn.isSessionResumed sys
        , wipeConnection = Conn.wipeConnection sys
        , freeHandshake = Conn.freeHandshake sys
        , releaseBuffers = Conn.releaseBuffers sys
        }
