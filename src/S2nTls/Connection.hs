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
    blockingNegotiate,

    -- * Data Transfer
    send,
    recv,
    blockingSend,
    blockingRecv,

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

import Control.Concurrent (threadWaitRead, threadWaitWrite)
import Data.ByteString (ByteString)
import Data.ByteString.Internal qualified as BS
import Data.ByteString.Unsafe qualified as BS
import Data.IORef (newIORef, readIORef, writeIORef)
import Foreign.C.Types (CInt (..))
import Foreign.Concurrent qualified as FC
import System.Posix.Types (Fd (..))
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
import S2nTls.Types (Config, Connection (..), Mode (..), TlsVersion (..))

{- | Create a new TLS connection.
The returned 'Connection' is automatically freed when garbage collected.
-}
newConnection :: (MonadIO m) => S2nTlsSys -> Mode -> m Connection
newConnection sys (Mode mode) = do
    ptr <- liftIO $ s2n_connection_new sys mode
    if ptr == nullPtr
        then throwS2nError sys
        else liftIO $ do
            fptr <- FC.newForeignPtr ptr (finalize ptr)
            readFdRef <- newIORef Nothing
            writeFdRef <- newIORef Nothing
            pure Connection
                { connPtr = fptr
                , connReadFd = readFdRef
                , connWriteFd = writeFdRef
                }
  where
    finalize :: Ptr S2nConnection -> IO ()
    finalize p = do
        _ <- s2n_connection_free sys p
        pure ()

-- | Set the configuration for a connection.
setConnectionConfig :: (MonadIO m) => S2nTlsSys -> Connection -> Config -> m ()
setConnectionConfig sys conn config =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            withForeignPtr config $ \configPtr ->
                checkReturn sys $
                    s2n_connection_set_config sys cPtr configPtr

-- | Set both read and write file descriptors for the connection.
setFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setFd sys conn fd =
    liftIO $ do
        withForeignPtr (connPtr conn) $ \cPtr ->
            checkReturn sys $
                s2n_connection_set_fd sys cPtr fd
        writeIORef (connReadFd conn) (Just fd)
        writeIORef (connWriteFd conn) (Just fd)

-- | Set the read file descriptor for the connection.
setReadFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setReadFd sys conn fd =
    liftIO $ do
        withForeignPtr (connPtr conn) $ \cPtr ->
            checkReturn sys $
                s2n_connection_set_read_fd sys cPtr fd
        writeIORef (connReadFd conn) (Just fd)

-- | Set the write file descriptor for the connection.
setWriteFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setWriteFd sys conn fd =
    liftIO $ do
        withForeignPtr (connPtr conn) $ \cPtr ->
            checkReturn sys $
                s2n_connection_set_write_fd sys cPtr fd
        writeIORef (connWriteFd conn) (Just fd)

{- | Set the server name for SNI (Server Name Indication).
This should be called before 'negotiate' for client connections.
-}
setServerName :: (MonadIO m) => S2nTlsSys -> Connection -> String -> m ()
setServerName sys conn name =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            withCString name $ \namePtr ->
                checkReturn sys $
                    s2n_set_server_name sys cPtr namePtr

{- | Get the server name from the connection.
Returns 'Nothing' if no server name is set.
-}
getServerName :: (MonadIO m) => S2nTlsSys -> Connection -> m (Maybe String)
getServerName sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr -> do
            namePtr <- s2n_get_server_name sys cPtr
            if namePtr == nullPtr
                then pure Nothing
                else Just <$> peekCString namePtr

{- | Perform the TLS handshake (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
Throws 'S2nError' on protocol errors or other failures.
-}
negotiate :: (MonadIO m) => S2nTlsSys -> Connection -> m (Either Blocked ())
negotiate sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                checkReturnWithBlocked sys blockedPtr $
                    s2n_negotiate sys cPtr blockedPtr

{- | Send data over the TLS connection (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right bytesSent' with the number of bytes sent.
Note: Not all bytes may be sent in one call; use a loop to send all data.
-}
send :: (MonadIO m) => S2nTlsSys -> Connection -> ByteString -> m (Either Blocked Int)
send sys conn bs =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            alloca $ \blockedPtr ->
                BS.unsafeUseAsCStringLen bs $ \(ptr, len) -> do
                    poke blockedPtr S2N_NOT_BLOCKED
                    result <-
                        s2n_send
                            sys
                            cPtr
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

{- | Receive data from the TLS connection (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right bytes' with the received data.
Returns an empty 'ByteString' if the connection was closed cleanly.
-}
recv :: (MonadIO m) => S2nTlsSys -> Connection -> Int -> m (Either Blocked ByteString)
recv sys conn maxLen =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                fptr <- BS.mallocByteString maxLen
                withForeignPtr fptr $ \ptr -> do
                    result <-
                        s2n_recv
                            sys
                            cPtr
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

{- | Shutdown the TLS connection (bidirectional, non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
-}
shutdown :: (MonadIO m) => S2nTlsSys -> Connection -> m (Either Blocked ())
shutdown sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                checkReturnWithBlocked sys blockedPtr $
                    s2n_shutdown sys cPtr blockedPtr

{- | Shutdown only the send side of the TLS connection (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
-}
shutdownSend :: (MonadIO m) => S2nTlsSys -> Connection -> m (Either Blocked ())
shutdownSend sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                checkReturnWithBlocked sys blockedPtr $
                    s2n_shutdown_send sys cPtr blockedPtr

{- | Get the negotiated application protocol (ALPN).
Returns 'Nothing' if no application protocol was negotiated.
-}
getApplicationProtocol :: (MonadIO m) => S2nTlsSys -> Connection -> m (Maybe String)
getApplicationProtocol sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr -> do
            protoPtr <- s2n_get_application_protocol sys cPtr
            if protoPtr == nullPtr
                then pure Nothing
                else Just <$> peekCString protoPtr

-- | Get the actual negotiated TLS protocol version.
getActualProtocolVersion :: (MonadIO m) => S2nTlsSys -> Connection -> m TlsVersion
getActualProtocolVersion sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr -> do
            version <- s2n_connection_get_actual_protocol_version sys cPtr
            pure (TlsVersion version)

-- | Get the negotiated cipher suite name.
getCipher :: (MonadIO m) => S2nTlsSys -> Connection -> m String
getCipher sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr -> do
            cipherPtr <- s2n_connection_get_cipher sys cPtr
            if cipherPtr == nullPtr
                then pure ""
                else peekCString cipherPtr

-- | Check if this connection is a resumed session.
isSessionResumed :: (MonadIO m) => S2nTlsSys -> Connection -> m Bool
isSessionResumed sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr -> do
            result <- s2n_connection_is_session_resumed sys cPtr
            pure (result /= 0)

{- | Wipe the connection for reuse.
This clears all connection state except the configuration.
-}
wipeConnection :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
wipeConnection sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            checkReturn sys $
                s2n_connection_wipe sys cPtr

{- | Free handshake-related memory after the handshake is complete.
This can reduce memory usage for long-lived connections.
-}
freeHandshake :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
freeHandshake sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            checkReturn sys $
                s2n_connection_free_handshake sys cPtr

-- | Release all buffers associated with the connection.
releaseBuffers :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
releaseBuffers sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            checkReturn sys $
                s2n_connection_release_buffers sys cPtr

{- | Perform the TLS handshake (blocking).
This function will block (using GHC's I/O manager) until the handshake
completes or an error occurs.
Throws 'S2nError' on protocol errors or other failures.
-}
blockingNegotiate :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
blockingNegotiate sys conn = go
  where
    go = do
        result <- negotiate sys conn
        case result of
            Right () -> pure ()
            Left blocked -> do
                liftIO $ waitOnBlocked conn blocked
                go

{- | Send data over the TLS connection (blocking).
This function will block (using GHC's I/O manager) until the data
is sent or an error occurs.
Returns the number of bytes sent.
Note: Not all bytes may be sent in one call; use a loop to send all data.
-}
blockingSend :: (MonadIO m) => S2nTlsSys -> Connection -> ByteString -> m Int
blockingSend sys conn bs = go
  where
    go = do
        result <- send sys conn bs
        case result of
            Right n -> pure n
            Left blocked -> do
                liftIO $ waitOnBlocked conn blocked
                go

{- | Receive data from the TLS connection (blocking).
This function will block (using GHC's I/O manager) until data is
available or an error occurs.
Returns the received data, or an empty 'ByteString' if the connection
was closed cleanly.
-}
blockingRecv :: (MonadIO m) => S2nTlsSys -> Connection -> Int -> m ByteString
blockingRecv sys conn maxLen = go
  where
    go = do
        result <- recv sys conn maxLen
        case result of
            Right bs -> pure bs
            Left blocked -> do
                liftIO $ waitOnBlocked conn blocked
                go

-- | Wait on a blocked status using GHC's I/O manager.
-- Uses readfd/writefd in preference to fd.
waitOnBlocked :: Connection -> Blocked -> IO ()
waitOnBlocked conn blocked = case blocked of
    BlockedOnRead -> do
        mFd <- getReadFd conn
        case mFd of
            Just fd -> threadWaitRead (Fd fd)
            Nothing -> pure () -- No fd set, just return
    BlockedOnWrite -> do
        mFd <- getWriteFd conn
        case mFd of
            Just fd -> threadWaitWrite (Fd fd)
            Nothing -> pure () -- No fd set, just return
    BlockedOnApplicationInput -> pure () -- Can't wait on this
    BlockedOnEarlyData -> pure () -- Can't wait on this

-- | Get the read file descriptor.
getReadFd :: Connection -> IO (Maybe CInt)
getReadFd conn = readIORef (connReadFd conn)

-- | Get the write file descriptor.
getWriteFd :: Connection -> IO (Maybe CInt)
getWriteFd conn = readIORef (connWriteFd conn)

-- Helper to convert blocked status to our Blocked type
toBlocked :: S2nBlockedStatus -> Maybe Blocked
toBlocked s = case s of
    S2N_NOT_BLOCKED -> Nothing
    S2N_BLOCKED_ON_READ -> Just BlockedOnRead
    S2N_BLOCKED_ON_WRITE -> Just BlockedOnWrite
    S2N_BLOCKED_ON_APPLICATION_INPUT -> Just BlockedOnApplicationInput
    S2N_BLOCKED_ON_EARLY_DATA -> Just BlockedOnEarlyData
    _ -> Nothing
