-- |
-- Module      : S2nTls.Connection
-- Copyright   : (c) 2025
-- License     : BSD-3-Clause
-- Maintainer  : your.email@example.com
-- Stability   : experimental
-- Portability : non-portable (requires s2n-tls C library)
--
-- This module provides functions for creating, configuring, and using
-- TLS connections. All I/O operations return @'Either' 'Blocked' a@ to handle
-- non-blocking scenarios gracefully.
--
{-# LANGUAGE PatternSynonyms #-}
module S2nTls.Connection (
    -- * Connection Creation
    newConnection,
    setConnectionConfig,

    -- * File Descriptor Setup
    setFd,
    setReadFd,
    setWriteFd,

    -- * Server Name (SNI)
    setServerName,
    getServerName,

    -- * TLS Handshake
    negotiate,

    -- * Data Transfer
    send,
    recv,

    -- * Connection Shutdown
    shutdown,
    shutdownSend,

    -- * Connection Info
    getApplicationProtocol,
    getActualProtocolVersion,
    getCipher,
    isSessionResumed,

    -- * Connection Management
    wipeConnection,
    freeHandshake,
    releaseBuffers,
) where

import Data.ByteString (ByteString)
import Data.ByteString.Internal qualified as BS
import Data.ByteString.Unsafe qualified as BS
import Foreign.C.Types (CInt (..))
import Foreign.Concurrent qualified as FC
import UnliftIO (MonadIO, liftIO)
import UnliftIO.Foreign (Ptr, alloca, castPtr, nullPtr, peek, peekCString, poke, withCString, withForeignPtr)
import S2nTls.Error (Blocked (..), checkReturn, checkReturnWithBlocked, throwS2nError)
import S2nTls.Sys.Types (
    S2nBlockedStatus (..),
    S2nConnection,
    S2nTlsSys (..),
    pattern S2N_BLOCKED_ON_APPLICATION_INPUT,
    pattern S2N_BLOCKED_ON_EARLY_DATA,
    pattern S2N_BLOCKED_ON_READ,
    pattern S2N_BLOCKED_ON_WRITE,
    pattern S2N_NOT_BLOCKED,
 )
import S2nTls.Types (Config, Connection, Mode (..), TlsVersion (..))

{- | Create a new TLS connection.
The returned 'Connection' is automatically freed when garbage collected.
-}
newConnection :: (MonadIO m) => S2nTlsSys -> Mode -> m Connection
newConnection sys (Mode mode) = do
    ptr <- liftIO $ s2n_connection_new sys mode
    if ptr == nullPtr
        then throwS2nError sys
        else liftIO $ FC.newForeignPtr ptr (finalize ptr)
  where
    finalize :: Ptr S2nConnection -> IO ()
    finalize p = do
        _ <- s2n_connection_free sys p
        pure ()

-- | Set the configuration for a connection.
setConnectionConfig :: (MonadIO m) => S2nTlsSys -> Connection -> Config -> m ()
setConnectionConfig sys conn config =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            withForeignPtr config $ \configPtr ->
                checkReturn sys $
                    s2n_connection_set_config sys connPtr configPtr

-- | Set both read and write file descriptors for the connection.
setFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setFd sys conn fd =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            checkReturn sys $
                s2n_connection_set_fd sys connPtr fd

-- | Set the read file descriptor for the connection.
setReadFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setReadFd sys conn fd =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            checkReturn sys $
                s2n_connection_set_read_fd sys connPtr fd

-- | Set the write file descriptor for the connection.
setWriteFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setWriteFd sys conn fd =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            checkReturn sys $
                s2n_connection_set_write_fd sys connPtr fd

{- | Set the server name for SNI (Server Name Indication).
This should be called before 'negotiate' for client connections.
-}
setServerName :: (MonadIO m) => S2nTlsSys -> Connection -> String -> m ()
setServerName sys conn name =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            withCString name $ \namePtr ->
                checkReturn sys $
                    s2n_set_server_name sys connPtr namePtr

{- | Get the server name from the connection.
Returns 'Nothing' if no server name is set.
-}
getServerName :: (MonadIO m) => S2nTlsSys -> Connection -> m (Maybe String)
getServerName sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr -> do
            namePtr <- s2n_get_server_name sys connPtr
            if namePtr == nullPtr
                then pure Nothing
                else Just <$> peekCString namePtr

{- | Perform the TLS handshake.
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
Throws 'S2nError' on protocol errors or other failures.
-}
negotiate :: (MonadIO m) => S2nTlsSys -> Connection -> m (Either Blocked ())
negotiate sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                checkReturnWithBlocked sys blockedPtr $
                    s2n_negotiate sys connPtr blockedPtr

{- | Send data over the TLS connection.
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right bytesSent' with the number of bytes sent.
Note: Not all bytes may be sent in one call; use a loop to send all data.
-}
send :: (MonadIO m) => S2nTlsSys -> Connection -> ByteString -> m (Either Blocked Int)
send sys conn bs =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            alloca $ \blockedPtr ->
                BS.unsafeUseAsCStringLen bs $ \(ptr, len) -> do
                    poke blockedPtr S2N_NOT_BLOCKED
                    result <-
                        s2n_send
                            sys
                            connPtr
                            (castPtr ptr)
                            (fromIntegral len)
                            blockedPtr
                    blocked <- peek blockedPtr
                    if result < 0
                        then do
                            case toBlocked blocked of
                                Just b -> pure (Left b)
                                Nothing -> throwS2nError sys
                        else pure (Right (fromIntegral result))

{- | Receive data from the TLS connection.
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right bytes' with the received data.
Returns an empty 'ByteString' if the connection was closed cleanly.
-}
recv :: (MonadIO m) => S2nTlsSys -> Connection -> Int -> m (Either Blocked ByteString)
recv sys conn maxLen =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                fptr <- BS.mallocByteString maxLen
                withForeignPtr fptr $ \ptr -> do
                    result <-
                        s2n_recv
                            sys
                            connPtr
                            (castPtr ptr)
                            (fromIntegral maxLen)
                            blockedPtr
                    blocked <- peek blockedPtr
                    if result < 0
                        then do
                            case toBlocked blocked of
                                Just b -> pure (Left b)
                                Nothing -> throwS2nError sys
                        else pure (Right (BS.fromForeignPtr fptr 0 (fromIntegral result)))

{- | Shutdown the TLS connection (bidirectional).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
-}
shutdown :: (MonadIO m) => S2nTlsSys -> Connection -> m (Either Blocked ())
shutdown sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                checkReturnWithBlocked sys blockedPtr $
                    s2n_shutdown sys connPtr blockedPtr

{- | Shutdown only the send side of the TLS connection.
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
-}
shutdownSend :: (MonadIO m) => S2nTlsSys -> Connection -> m (Either Blocked ())
shutdownSend sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                checkReturnWithBlocked sys blockedPtr $
                    s2n_shutdown_send sys connPtr blockedPtr

{- | Get the negotiated application protocol (ALPN).
Returns 'Nothing' if no application protocol was negotiated.
-}
getApplicationProtocol :: (MonadIO m) => S2nTlsSys -> Connection -> m (Maybe String)
getApplicationProtocol sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr -> do
            protoPtr <- s2n_get_application_protocol sys connPtr
            if protoPtr == nullPtr
                then pure Nothing
                else Just <$> peekCString protoPtr

-- | Get the actual negotiated TLS protocol version.
getActualProtocolVersion :: (MonadIO m) => S2nTlsSys -> Connection -> m TlsVersion
getActualProtocolVersion sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr -> do
            version <- s2n_connection_get_actual_protocol_version sys connPtr
            pure (TlsVersion version)

-- | Get the negotiated cipher suite name.
getCipher :: (MonadIO m) => S2nTlsSys -> Connection -> m String
getCipher sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr -> do
            cipherPtr <- s2n_connection_get_cipher sys connPtr
            if cipherPtr == nullPtr
                then pure ""
                else peekCString cipherPtr

-- | Check if this connection is a resumed session.
isSessionResumed :: (MonadIO m) => S2nTlsSys -> Connection -> m Bool
isSessionResumed sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr -> do
            result <- s2n_connection_is_session_resumed sys connPtr
            pure (result /= 0)

{- | Wipe the connection for reuse.
This clears all connection state except the configuration.
-}
wipeConnection :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
wipeConnection sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            checkReturn sys $
                s2n_connection_wipe sys connPtr

{- | Free handshake-related memory after the handshake is complete.
This can reduce memory usage for long-lived connections.
-}
freeHandshake :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
freeHandshake sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            checkReturn sys $
                s2n_connection_free_handshake sys connPtr

-- | Release all buffers associated with the connection.
releaseBuffers :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
releaseBuffers sys conn =
    liftIO $
        withForeignPtr conn $ \connPtr ->
            checkReturn sys $
                s2n_connection_release_buffers sys connPtr

-- Helper to convert blocked status to our Blocked type
toBlocked :: S2nBlockedStatus -> Maybe Blocked
toBlocked s = case s of
    S2N_NOT_BLOCKED -> Nothing
    S2N_BLOCKED_ON_READ -> Just BlockedOnRead
    S2N_BLOCKED_ON_WRITE -> Just BlockedOnWrite
    S2N_BLOCKED_ON_APPLICATION_INPUT -> Just BlockedOnApplicationInput
    S2N_BLOCKED_ON_EARLY_DATA -> Just BlockedOnEarlyData
    _ -> Nothing
