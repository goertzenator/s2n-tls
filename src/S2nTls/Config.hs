-- |
-- Module      : S2nTls.Config
-- Copyright   : (c) 2025
-- License     : BSD-3-Clause
-- Maintainer  : your.email@example.com
-- Stability   : experimental
-- Portability : non-portable (requires s2n-tls C library)
--
-- This module provides functions for creating and configuring TLS configurations.
--
module S2nTls.Config (
    -- * Configuration Creation
    newConfig,
    newConfigMinimal,

    -- * Certificate Management
    newCertChainAndKey,
    loadCertChainAndKeyPem,
    addCertChainAndKeyToStore,

    -- * Trust Store
    setVerificationCaLocation,
    addPemToTrustStore,
    wipeTrustStore,
    loadSystemCerts,

    -- * Security Settings
    setCipherPreferences,
    setClientAuthType,
    disableX509Verification,

    -- * Protocol Settings
    setProtocolPreferences,
) where

import Data.ByteString (ByteString)
import Data.ByteString.Unsafe qualified as BS
import Foreign.C.String (CString)
import Foreign.Concurrent qualified as FC
import UnliftIO (MonadIO, liftIO)
import UnliftIO.Foreign (Ptr, castPtr, nullPtr, withArray, withCString, withForeignPtr)
import S2nTls.Error (checkReturn, throwS2nError)
import S2nTls.Sys.Types (
    S2nCertChainAndKey,
    S2nConfig,
    S2nTlsSys (..),
 )
import S2nTls.Types (CertAuthType (..), CertChainAndKey, Config)

{- | Create a new TLS configuration with default settings.
The returned 'Config' is automatically freed when garbage collected.
-}
newConfig :: (MonadIO m) => S2nTlsSys -> m Config
newConfig sys = do
    ptr <- liftIO $ s2n_config_new sys
    if ptr == nullPtr
        then throwS2nError sys
        else liftIO $ FC.newForeignPtr ptr (finalize ptr)
  where
    finalize :: Ptr S2nConfig -> IO ()
    finalize p = do
        _ <- s2n_config_free sys p
        pure ()

{- | Create a new minimal TLS configuration.
This configuration has fewer default settings than 'newConfig'.
-}
newConfigMinimal :: (MonadIO m) => S2nTlsSys -> m Config
newConfigMinimal sys = do
    ptr <- liftIO $ s2n_config_new_minimal sys
    if ptr == nullPtr
        then throwS2nError sys
        else liftIO $ FC.newForeignPtr ptr (finalize ptr)
  where
    finalize :: Ptr S2nConfig -> IO ()
    finalize p = do
        _ <- s2n_config_free sys p
        pure ()

{- | Create a new certificate chain and key pair.
The returned value is automatically freed when garbage collected.
-}
newCertChainAndKey :: (MonadIO m) => S2nTlsSys -> m CertChainAndKey
newCertChainAndKey sys = do
    ptr <- liftIO $ s2n_cert_chain_and_key_new sys
    if ptr == nullPtr
        then throwS2nError sys
        else liftIO $ FC.newForeignPtr ptr (finalize ptr)
  where
    finalize :: Ptr S2nCertChainAndKey -> IO ()
    finalize p = do
        _ <- s2n_cert_chain_and_key_free sys p
        pure ()

-- | Load a certificate chain and private key from PEM data.
loadCertChainAndKeyPem ::
    (MonadIO m) =>
    S2nTlsSys ->
    -- | Certificate chain and key to load into
    CertChainAndKey ->
    -- | Certificate chain PEM data
    ByteString ->
    -- | Private key PEM data
    ByteString ->
    m ()
loadCertChainAndKeyPem sys certKey certPem keyPem =
    liftIO $
        withForeignPtr certKey $ \certKeyPtr ->
            BS.unsafeUseAsCStringLen certPem $ \(certPtr, certLen) ->
                BS.unsafeUseAsCStringLen keyPem $ \(keyPtr, keyLen) ->
                    checkReturn sys $
                        s2n_cert_chain_and_key_load_pem_bytes
                            sys
                            certKeyPtr
                            (castPtr certPtr)
                            (fromIntegral certLen)
                            (castPtr keyPtr)
                            (fromIntegral keyLen)

-- | Add a certificate chain and key to a configuration's store.
addCertChainAndKeyToStore ::
    (MonadIO m) =>
    S2nTlsSys ->
    Config ->
    CertChainAndKey ->
    m ()
addCertChainAndKeyToStore sys config certKey =
    liftIO $
        withForeignPtr config $ \configPtr ->
            withForeignPtr certKey $ \certKeyPtr ->
                checkReturn sys $
                    s2n_config_add_cert_chain_and_key_to_store sys configPtr certKeyPtr

-- | Set the CA certificate locations for verification.
setVerificationCaLocation ::
    (MonadIO m) =>
    S2nTlsSys ->
    Config ->
    -- | Path to CA certificate file (or Nothing)
    Maybe FilePath ->
    -- | Path to CA certificate directory (or Nothing)
    Maybe FilePath ->
    m ()
setVerificationCaLocation sys config mFile mDir =
    liftIO $
        withForeignPtr config $ \configPtr ->
            withMaybeCString mFile $ \filePtr ->
                withMaybeCString mDir $ \dirPtr ->
                    checkReturn sys $
                        s2n_config_set_verification_ca_location sys configPtr filePtr dirPtr

-- | Add a PEM certificate to the trust store.
addPemToTrustStore ::
    (MonadIO m) =>
    S2nTlsSys ->
    Config ->
    -- | PEM-encoded certificate
    String ->
    m ()
addPemToTrustStore sys config pem =
    liftIO $
        withForeignPtr config $ \configPtr ->
            withCString pem $ \pemPtr ->
                checkReturn sys $
                    s2n_config_add_pem_to_trust_store sys configPtr pemPtr

-- | Clear the trust store.
wipeTrustStore :: (MonadIO m) => S2nTlsSys -> Config -> m ()
wipeTrustStore sys config =
    liftIO $
        withForeignPtr config $ \configPtr ->
            checkReturn sys $
                s2n_config_wipe_trust_store sys configPtr

-- | Load system CA certificates into the trust store.
loadSystemCerts :: (MonadIO m) => S2nTlsSys -> Config -> m ()
loadSystemCerts sys config =
    liftIO $
        withForeignPtr config $ \configPtr ->
            checkReturn sys $
                s2n_config_load_system_certs sys configPtr

{- | Set the cipher preferences using a security policy name.
Common values include "default", "default_tls13", "20170210", etc.
-}
setCipherPreferences ::
    (MonadIO m) =>
    S2nTlsSys ->
    Config ->
    -- | Security policy name
    String ->
    m ()
setCipherPreferences sys config policy =
    liftIO $
        withForeignPtr config $ \configPtr ->
            withCString policy $ \policyPtr ->
                checkReturn sys $
                    s2n_config_set_cipher_preferences sys configPtr policyPtr

-- | Set the client certificate authentication type.
setClientAuthType ::
    (MonadIO m) =>
    S2nTlsSys ->
    Config ->
    CertAuthType ->
    m ()
setClientAuthType sys config (CertAuthType authType) =
    liftIO $
        withForeignPtr config $ \configPtr ->
            checkReturn sys $
                s2n_config_set_client_auth_type sys configPtr authType

{- | Disable X.509 certificate verification.
WARNING: This is insecure and should only be used for testing.
-}
disableX509Verification :: (MonadIO m) => S2nTlsSys -> Config -> m ()
disableX509Verification sys config =
    liftIO $
        withForeignPtr config $ \configPtr ->
            checkReturn sys $
                s2n_config_disable_x509_verification sys configPtr

-- | Set the application protocol preferences (ALPN).
setProtocolPreferences ::
    (MonadIO m) =>
    S2nTlsSys ->
    Config ->
    -- | List of protocol names in preference order
    [String] ->
    m ()
setProtocolPreferences sys config protocols =
    liftIO $
        withForeignPtr config $ \configPtr ->
            withCStrings protocols $ \protoPtrs ->
                withArray protoPtrs $ \protoArray ->
                    checkReturn sys $
                        s2n_config_set_protocol_preferences
                            sys
                            configPtr
                            protoArray
                            (fromIntegral $ length protocols)

-- Helper functions

withMaybeCString :: Maybe String -> (CString -> IO a) -> IO a
withMaybeCString Nothing f = f nullPtr
withMaybeCString (Just s) f = withCString s f

withCStrings :: [String] -> ([CString] -> IO a) -> IO a
withCStrings [] f = f []
withCStrings (s : ss) f = withCString s $ \p -> withCStrings ss $ \ps -> f (p : ps)
