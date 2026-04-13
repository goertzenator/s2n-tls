{- |
Module      : S2nTls.Config
Copyright   : (c) 2026
License     : BSD-3-Clause
Maintainer  : daniel.goertzen@gmail.com

This module provides functions for creating and configuring TLS configurations.
-}
module S2nTls.Config (
    -- * Configuration Creation
    newConfig,
    newConfigMinimal,

    -- * Certificate Management
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

import Control.Exception (mask_, throwIO)
import Control.Monad
import Data.ByteString (ByteString)
import Data.ByteString.Unsafe qualified as BS
import Data.IORef (modifyIORef', newIORef)
import Foreign (Ptr, castPtr, nullPtr, withArray, withForeignPtr)
import Foreign.C.String (CString, withCString)
import Foreign.Concurrent qualified as FC
import S2nTls.Error (fromFfiEither, fromFfiError)
import S2nTls.Ffi.Types (
    S2nCertChainAndKey,
    S2nConfig,
    S2nTlsFfi (..),
 )
import S2nTls.Types (CertAuthType (..), CertChainAndKey, Config (..))

{- | Create a new TLS configuration with default settings.
The returned 'Config' is automatically freed when garbage collected.
-}
newConfig :: S2nTlsFfi -> IO Config
newConfig ffi = mask_ $ do
    result <- s2n_config_new ffi
    case result of
        Left err -> fromFfiError ffi err >>= throwIO
        Right ptr -> do
            fptr <- FC.newForeignPtr ptr (finalize ptr)
            certKeysRef <- newIORef []
            pure
                Config
                    { configPtr = fptr
                    , configCertKeys = certKeysRef
                    }
  where
    finalize :: Ptr S2nConfig -> IO ()
    finalize p = do
        _ <- s2n_config_free ffi p
        pure ()

{- | Create a new minimal TLS configuration.
This configuration has fewer default settings than 'newConfig'.
-}
newConfigMinimal :: S2nTlsFfi -> IO Config
newConfigMinimal ffi = mask_ $ do
    result <- s2n_config_new_minimal ffi
    case result of
        Left err -> fromFfiError ffi err >>= throwIO
        Right ptr -> do
            fptr <- FC.newForeignPtr ptr (finalize ptr)
            certKeysRef <- newIORef []
            pure
                Config
                    { configPtr = fptr
                    , configCertKeys = certKeysRef
                    }
  where
    finalize :: Ptr S2nConfig -> IO ()
    finalize p = do
        _ <- s2n_config_free ffi p
        pure ()

{- | Create a new certificate chain and key pair.
The returned value is automatically freed when garbage collected.
-}
newCertChainAndKey :: S2nTlsFfi -> IO CertChainAndKey
newCertChainAndKey ffi = mask_ $ do
    result <- s2n_cert_chain_and_key_new ffi
    case result of
        Left err -> fromFfiError ffi err >>= throwIO
        Right ptr -> FC.newForeignPtr ptr (finalize ptr)
  where
    finalize :: Ptr S2nCertChainAndKey -> IO ()
    finalize p = do
        _ <- s2n_cert_chain_and_key_free ffi p
        pure ()

-- | Load a certificate chain and private key from PEM data.
loadCertChainAndKeyPem ::
    S2nTlsFfi ->
    -- | Certificate chain PEM data
    ByteString ->
    -- | Private key PEM data
    ByteString ->
    IO CertChainAndKey
loadCertChainAndKeyPem ffi certPem keyPem = do
    certKey <- newCertChainAndKey ffi
    void $
        withForeignPtr certKey $ \certKeyPtr ->
            BS.unsafeUseAsCStringLen certPem $ \(certPtr, certLen) ->
                BS.unsafeUseAsCStringLen keyPem $ \(keyPtr, keyLen) ->
                    s2n_cert_chain_and_key_load_pem_bytes
                        ffi
                        certKeyPtr
                        (castPtr certPtr)
                        (fromIntegral certLen)
                        (castPtr keyPtr)
                        (fromIntegral keyLen)
                        >>= fromFfiEither ffi
    pure certKey

-- | Add a certificate chain and key to a configuration's store.
addCertChainAndKeyToStore ::
    S2nTlsFfi ->
    Config ->
    CertChainAndKey ->
    IO ()
addCertChainAndKeyToStore ffi config certKey = do
    void $ withForeignPtr (configPtr config) $ \cPtr ->
        withForeignPtr certKey $
            s2n_config_add_cert_chain_and_key_to_store ffi cPtr >=> fromFfiEither ffi
    -- Keep the cert key alive by storing a reference
    modifyIORef' (configCertKeys config) (certKey :)

-- | Set the CA certificate locations for verification.
setVerificationCaLocation ::
    S2nTlsFfi ->
    Config ->
    -- | Path to CA certificate file (or Nothing)
    Maybe FilePath ->
    -- | Path to CA certificate directory (or Nothing)
    Maybe FilePath ->
    IO ()
setVerificationCaLocation ffi config mFile mDir =
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            withMaybeCString mFile $ \filePtr ->
                withMaybeCString mDir $
                    s2n_config_set_verification_ca_location ffi cPtr filePtr >=> fromFfiEither ffi

-- | Add a PEM certificate to the trust store.
addPemToTrustStore ::
    S2nTlsFfi ->
    Config ->
    -- | PEM-encoded certificate
    String ->
    IO ()
addPemToTrustStore ffi config pem =
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            withCString pem $
                s2n_config_add_pem_to_trust_store ffi cPtr >=> fromFfiEither ffi

-- | Clear the trust store.
wipeTrustStore :: S2nTlsFfi -> Config -> IO ()
wipeTrustStore ffi config =
    void $
        withForeignPtr (configPtr config) $
            s2n_config_wipe_trust_store ffi >=> fromFfiEither ffi

-- | Load system CA certificates into the trust store.
loadSystemCerts :: S2nTlsFfi -> Config -> IO ()
loadSystemCerts ffi config =
    void $
        withForeignPtr (configPtr config) $
            s2n_config_load_system_certs ffi >=> fromFfiEither ffi

{- | Set the cipher preferences using a security policy name.
Common values include "default", "default_fips", "default_tls13",
"rfc9151", "20170210", etc.
-}
setCipherPreferences ::
    S2nTlsFfi ->
    Config ->
    -- | Security policy name
    String ->
    IO ()
setCipherPreferences ffi config policy =
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            withCString policy $
                s2n_config_set_cipher_preferences ffi cPtr >=> fromFfiEither ffi

-- | Set the client certificate authentication type.
setClientAuthType ::
    S2nTlsFfi ->
    Config ->
    CertAuthType ->
    IO ()
setClientAuthType ffi config (CertAuthType authType) =
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            s2n_config_set_client_auth_type ffi cPtr authType >>= fromFfiEither ffi

{- | Disable X.509 certificate verification.
WARNING: This is insecure and should only be used for testing.
-}
disableX509Verification :: S2nTlsFfi -> Config -> IO ()
disableX509Verification ffi config =
    void $
        withForeignPtr (configPtr config) $
            s2n_config_disable_x509_verification ffi >=> fromFfiEither ffi

-- | Set the application protocol preferences (ALPN).
setProtocolPreferences ::
    S2nTlsFfi ->
    Config ->
    -- | List of protocol names in preference order
    [String] ->
    IO ()
setProtocolPreferences ffi config protocols =
    void $
        withForeignPtr (configPtr config) $ \cfgPtr ->
            withCStrings protocols $ \protoPtrs ->
                withArray protoPtrs $ \protoArray ->
                    s2n_config_set_protocol_preferences
                        ffi
                        cfgPtr
                        protoArray
                        (fromIntegral $ length protocols)
                        >>= fromFfiEither ffi

-- Helper functions

withMaybeCString :: Maybe String -> (CString -> IO a) -> IO a
withMaybeCString Nothing f = f nullPtr
withMaybeCString (Just s) f = withCString s f

withCStrings :: [String] -> ([CString] -> IO a) -> IO a
withCStrings [] f = f []
withCStrings (s : ss) f = withCString s $ \p -> withCStrings ss $ \ps -> f (p : ps)
