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

    -- * Session Tickets
    setSessionTicketsOnOff,
    addTicketCryptoKey,
    setTicketDecryptKeyLifetime,
    setTicketEncryptDecryptKeyLifetime,
    setSessionTicketCallback,
) where

import Control.Exception (SomeException, mask_, throwIO, try)
import Control.Monad
import Control.Monad.Primitive
import Data.ByteString (ByteString)
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe qualified as BS
import Data.Foldable (traverse_)
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import Data.Maybe (fromMaybe)
import Data.Word (Word32, Word64)
import Foreign (Ptr, alloca, castPtr, mallocForeignPtrBytes, nullPtr, peek, touchForeignPtr, withArray, withForeignPtr)
import Foreign.C.String (CString, withCString)
import Foreign.C.Types (CInt (..))
import Foreign.Concurrent qualified as FC
import Foreign.Ptr (FunPtr)
import S2nTls.Error (fromFfiEither, fromFfiError)
import S2nTls.Ffi.Types (
    S2nCertChainAndKey,
    S2nConnection,
    S2nSessionTicket,
    S2nSessionTicketFn,
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
            certKeysRef <- newIORef []
            sessionTicketCbRef <- newIORef Nothing
            let
                finalize :: IO ()
                finalize = do
                    -- ensure all related resources are kept alive until after s2n_config_free is called
                    void $ keepAlive (certKeysRef, sessionTicketCbRef) $ do
                        s2n_config_free ffi ptr

            fptr <- FC.newForeignPtr ptr finalize
            pure
                Config
                    { configPtr = fptr
                    , configCertKeys = certKeysRef
                    , configSessionTicketCb = sessionTicketCbRef
                    }

{- | Create a new minimal TLS configuration.
This configuration has fewer default settings than 'newConfig'.
-}
newConfigMinimal :: S2nTlsFfi -> IO Config
newConfigMinimal ffi = mask_ $ do
    result <- s2n_config_new_minimal ffi
    case result of
        Left err -> fromFfiError ffi err >>= throwIO
        Right ptr -> do
            certKeysRef <- newIORef []
            sessionTicketCbRef <- newIORef Nothing
            let
                finalize :: IO ()
                finalize = do
                    _ <- s2n_config_free ffi ptr
                    -- Touch stored items to keep them alive during s2n_config_free
                    readIORef certKeysRef >>= traverse_ touchForeignPtr
                    readIORef sessionTicketCbRef >>= traverse_ touchFunPtr
                touchFunPtr :: FunPtr a -> IO ()
                touchFunPtr !_ = pure ()
            fptr <- FC.newForeignPtr ptr finalize
            pure
                Config
                    { configPtr = fptr
                    , configCertKeys = certKeysRef
                    , configSessionTicketCb = sessionTicketCbRef
                    }

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

-- Session Tickets

{- | Enable or disable session tickets.

For servers, this enables sending session tickets to clients.
For clients, this enables receiving and storing session tickets.
-}
setSessionTicketsOnOff :: S2nTlsFfi -> Config -> Bool -> IO ()
setSessionTicketsOnOff ffi config enabled =
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            s2n_config_set_session_tickets_onoff ffi cPtr (if enabled then 1 else 0)
                >>= fromFfiEither ffi

{- | Add an encryption key for session tickets.

This is the only function that may safely mutate a Config after it has been
assigned to a Connection.

The key name should be a unique identifier for this key (used for key rotation).
The key should be 32 bytes of cryptographically random data.

The introduction time specifies when this key becomes valid:
- @Nothing@: The key is valid immediately (start time = 0, meaning now)
- @Just time@: The key becomes valid at the specified Unix epoch time (seconds)
-}
addTicketCryptoKey ::
    S2nTlsFfi ->
    Config ->
    -- | Key name (unique identifier for key rotation)
    ByteString ->
    -- | Key data (should be 32 random bytes)
    ByteString ->
    -- | Introduction time (@Nothing@ = now)
    Maybe Word64 ->
    IO ()
addTicketCryptoKey ffi config keyName key introTime =
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            BS.unsafeUseAsCStringLen keyName $ \(namePtr, nameLen) ->
                BS.unsafeUseAsCStringLen key $ \(keyPtr, keyLen) ->
                    s2n_config_add_ticket_crypto_key
                        ffi
                        cPtr
                        (castPtr namePtr)
                        (fromIntegral nameLen)
                        (castPtr keyPtr)
                        (fromIntegral keyLen)
                        (fromMaybe 0 introTime)
                        >>= fromFfiEither ffi

{- | Set the lifetime (in seconds) for which a session ticket key can be used
for decryption only (after it can no longer encrypt).

This allows for graceful key rotation by continuing to accept tickets encrypted
with an older key while new tickets use a newer key.
-}
setTicketDecryptKeyLifetime :: S2nTlsFfi -> Config -> Word64 -> IO ()
setTicketDecryptKeyLifetime ffi config lifetime =
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            s2n_config_set_ticket_decrypt_key_lifetime ffi cPtr lifetime
                >>= fromFfiEither ffi

{- | Set the lifetime (in seconds) for which a session ticket key can be used
for both encryption and decryption.

After this time, the key will only be used for decryption (for the duration
set by 'setTicketDecryptKeyLifetime').
-}
setTicketEncryptDecryptKeyLifetime :: S2nTlsFfi -> Config -> Word64 -> IO ()
setTicketEncryptDecryptKeyLifetime ffi config lifetime =
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            s2n_config_set_ticket_encrypt_decrypt_key_lifetime ffi cPtr lifetime
                >>= fromFfiEither ffi

{- | Set a callback to receive session tickets from the server.

This is used by clients to store session tickets for later resumption.
The callback receives the session ticket data (as a 'ByteString') and
the ticket lifetime in seconds. The callback should store this data and
return 'True'. The stored data can later be passed to
'S2nTls.Connection.setSession' to resume the session.
-}
setSessionTicketCallback ::
    S2nTlsFfi ->
    Config ->
    -- | Callback that receives ticket data and lifetime
    (ByteString -> Word32 -> IO ()) ->
    IO ()
setSessionTicketCallback ffi config callback = do
    funPtr <- wrapSessionTicketCallback $ \_connPtr _ctx ticketPtr -> do
        -- Get the ticket data length
        ticketLen <- getSessionTicketDataLen ffi ticketPtr
        -- Get the ticket data
        ticketData <- getSessionTicketData ffi ticketPtr ticketLen
        -- Get the ticket lifetime
        lifetime <- getSessionTicketLifetime ffi ticketPtr
        -- Call the user callback
        result <- try @SomeException (callback ticketData lifetime)
        case result of
            Left _e -> pure (-1)
            Right () -> pure 0
    void $
        withForeignPtr (configPtr config) $ \cPtr ->
            s2n_config_set_session_ticket_cb ffi cPtr funPtr nullPtr
                >>= fromFfiEither ffi
    -- Keep the FunPtr alive by storing it in the config
    writeIORef (configSessionTicketCb config) (Just funPtr)

-- | FFI wrapper for creating a session ticket callback FunPtr
foreign import ccall "wrapper"
    wrapSessionTicketCallback ::
        (Ptr S2nConnection -> Ptr () -> Ptr S2nSessionTicket -> IO CInt) ->
        IO S2nSessionTicketFn

-- | Get the length of session ticket data
getSessionTicketDataLen :: S2nTlsFfi -> Ptr S2nSessionTicket -> IO Int
getSessionTicketDataLen ffi ticketPtr =
    alloca $ \lenPtr -> do
        void $ s2n_session_ticket_get_data_len ffi ticketPtr lenPtr >>= fromFfiEither ffi
        len <- peek lenPtr
        pure (fromIntegral len)

-- | Get session ticket data
getSessionTicketData :: S2nTlsFfi -> Ptr S2nSessionTicket -> Int -> IO ByteString
getSessionTicketData ffi ticketPtr len = do
    fptr <- mallocForeignPtrBytes len
    withForeignPtr fptr $ \bufPtr -> do
        void $
            s2n_session_ticket_get_data ffi ticketPtr (fromIntegral len) (castPtr bufPtr)
                >>= fromFfiEither ffi
    pure (BSI.fromForeignPtr fptr 0 len)

-- | Get session ticket lifetime
getSessionTicketLifetime :: S2nTlsFfi -> Ptr S2nSessionTicket -> IO Word32
getSessionTicketLifetime ffi ticketPtr =
    alloca $ \lifetimePtr -> do
        void $ s2n_session_ticket_get_lifetime ffi ticketPtr lifetimePtr >>= fromFfiEither ffi
        peek lifetimePtr
