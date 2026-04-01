-- |
-- Module      : S2nTls
-- Copyright   : (c) 2025
-- License     : BSD-3-Clause
-- Maintainer  : your.email@example.com
-- Stability   : experimental
-- Portability : non-portable (requires s2n-tls C library)
--
{-# LANGUAGE PatternSynonyms #-}
{-# LANGUAGE RankNTypes #-}

{- |
Module      : S2nTls
Description : High-level Haskell bindings to s2n-tls
License     : BSD-3-Clause

This module provides safe, high-level Haskell bindings to the s2n-tls library.
It wraps the low-level FFI bindings from "S2nTls.Sys" with:

* Automatic memory management using 'ForeignPtr'
* Haskell-idiomatic error handling with exceptions and 'Either'
* Library initialization and cleanup via 'withS2nTls'

= Basic Usage

@
import S2nTls
import S2nTls.Sys (getLinkedTlsSys)

main :: IO ()
main = withS2nTls getLinkedTlsSys $ \\tls -> do
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

    -- Send data
    send tls conn "GET / HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"

    -- Receive data
    response <- recv tls conn 4096
    ...
@
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

import UnliftIO (MonadIO, MonadUnliftIO, withRunInIO)
import Data.ByteString (ByteString)
import Foreign.C.Types (CInt)
import S2nTls.Config qualified as Config
import S2nTls.Connection qualified as Conn
import S2nTls.Error (S2nError (..), S2nErrorType (..), checkReturn)
import S2nTls.Sys.Types (S2nTlsSys (..))
import S2nTls.Types

{- | A record containing all high-level s2n-tls operations.
This record is provided by 'withS2nTls' and provides a convenient
way to access all TLS functionality.
-}
data S2nTls = S2nTls
  { newConfig :: forall m. (MonadIO m) => m Config
  -- ^ Create a new TLS configuration with default settings.
  , newConfigMinimal :: forall m. (MonadIO m) => m Config
  -- ^ Create a new minimal TLS configuration.
  , newCertChainAndKey :: forall m. (MonadIO m) => m CertChainAndKey
  -- ^ Create a new certificate chain and key pair.
  , loadCertChainAndKeyPem ::
      forall m.
      (MonadIO m) =>
      CertChainAndKey ->
      -- | Certificate chain PEM
      ByteString ->
      -- | Private key PEM
      ByteString ->
      m ()
  -- ^ Load a certificate chain and private key from PEM data.
  , addCertChainAndKeyToStore :: forall m. (MonadIO m) => Config -> CertChainAndKey -> m ()
  -- ^ Add a certificate chain and key to a configuration's store.
  , setVerificationCaLocation ::
      forall m.
      (MonadIO m) =>
      Config ->
      -- | CA file path
      Maybe FilePath ->
      -- | CA directory path
      Maybe FilePath ->
      m ()
  -- ^ Set the CA certificate locations for verification.
  , addPemToTrustStore ::
      forall m.
      (MonadIO m) =>
      Config ->
      -- | PEM-encoded certificate
      String ->
      m ()
  -- ^ Add a PEM certificate to the trust store.
  , wipeTrustStore :: forall m. (MonadIO m) => Config -> m ()
  -- ^ Clear the trust store.
  , loadSystemCerts :: forall m. (MonadIO m) => Config -> m ()
  -- ^ Load system CA certificates into the trust store.
  , setCipherPreferences ::
      forall m.
      (MonadIO m) =>
      Config ->
      -- | Security policy name
      String ->
      m ()
  -- ^ Set cipher preferences using a security policy name.
  , setClientAuthType :: forall m. (MonadIO m) => Config -> CertAuthType -> m ()
  -- ^ Set client certificate authentication type.
  , disableX509Verification :: forall m. (MonadIO m) => Config -> m ()
  -- ^ Disable X.509 certificate verification (insecure!).
  , setProtocolPreferences ::
      forall m.
      (MonadIO m) =>
      Config ->
      -- | List of protocol names
      [String] ->
      m ()
  -- ^ Set application protocol preferences (ALPN).
  , newConnection :: forall m. (MonadIO m) => Mode -> m Connection
  -- ^ Create a new TLS connection.
  , setConnectionConfig :: forall m. (MonadIO m) => Connection -> Config -> m ()
  -- ^ Set the configuration for a connection.
  , setFd :: forall m. (MonadIO m) => Connection -> CInt -> m ()
  -- ^ Set both read and write file descriptors.
  , setReadFd :: forall m. (MonadIO m) => Connection -> CInt -> m ()
  -- ^ Set the read file descriptor.
  , setWriteFd :: forall m. (MonadIO m) => Connection -> CInt -> m ()
  -- ^ Set the write file descriptor.
  , setServerName :: forall m. (MonadIO m) => Connection -> String -> m ()
  -- ^ Set the server name for SNI.
  , getServerName :: forall m. (MonadIO m) => Connection -> m (Maybe String)
  -- ^ Get the server name from the connection.
  , negotiate :: forall m. (MonadIO m) => Connection -> m (Either Blocked ())
  -- ^ Perform the TLS handshake.
  , send :: forall m. (MonadIO m) => Connection -> ByteString -> m (Either Blocked Int)
  -- ^ Send data over the TLS connection.
  , recv ::
      forall m.
      (MonadIO m) =>
      Connection ->
      -- | Maximum bytes to receive
      Int ->
      m (Either Blocked ByteString)
  -- ^ Receive data from the TLS connection.
  , shutdown :: forall m. (MonadIO m) => Connection -> m (Either Blocked ())
  -- ^ Shutdown the TLS connection (bidirectional).
  , shutdownSend :: forall m. (MonadIO m) => Connection -> m (Either Blocked ())
  -- ^ Shutdown only the send side.
  , getApplicationProtocol :: forall m. (MonadIO m) => Connection -> m (Maybe String)
  -- ^ Get the negotiated application protocol (ALPN).
  , getActualProtocolVersion :: forall m. (MonadIO m) => Connection -> m TlsVersion
  -- ^ Get the actual negotiated TLS protocol version.
  , getCipher :: forall m. (MonadIO m) => Connection -> m String
  -- ^ Get the negotiated cipher suite name.
  , isSessionResumed :: forall m. (MonadIO m) => Connection -> m Bool
  -- ^ Check if this is a resumed session.
  , wipeConnection :: forall m. (MonadIO m) => Connection -> m ()
  -- ^ Wipe the connection for reuse.
  , freeHandshake :: forall m. (MonadIO m) => Connection -> m ()
  -- ^ Free handshake-related memory.
  , releaseBuffers :: forall m. (MonadIO m) => Connection -> m ()
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
    config <- newConfig tls
    -- ... use the TLS API ...
@
-}
withS2nTls :: (MonadUnliftIO m) => S2nTlsSys -> (S2nTls -> m a) -> m a
withS2nTls sys action = withRunInIO $ \runInIO -> do
    checkReturn sys $ s2n_init sys
    result <- runInIO (action (mkS2nTls sys))
    _ <- s2n_cleanup sys
    pure result

-- | Create the S2nTls record from the low-level sys bindings.
mkS2nTls :: S2nTlsSys -> S2nTls
mkS2nTls sys =
  S2nTls
    { newConfig = Config.newConfig sys
    , newConfigMinimal = Config.newConfigMinimal sys
    , newCertChainAndKey = Config.newCertChainAndKey sys
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
    , send = Conn.send sys
    , recv = Conn.recv sys
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
