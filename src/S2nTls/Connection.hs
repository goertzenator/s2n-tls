{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : S2nTls.Connection
Copyright   : (c) 2026
License     : BSD-3-Clause
Maintainer  : daniel.goertzen@gmail.com

This module provides functions for creating, configuring, and using
TLS connections. All I/O operations return @'Either' 'Blocked' a@ to handle
non-blocking scenarios gracefully.
-}
module S2nTls.Connection (
    -- * Connection Creation
    newConnection,
    setConnectionConfig,

    -- * File Descriptor Setup
    setFd,
    setReadFd,
    setWriteFd,
    setSocket,

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
    blockingSendAll,
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
import Control.Exception (mask_, throwIO)
import Control.Monad
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe qualified as BS
import Data.Foldable
import Data.IORef (newIORef, readIORef, writeIORef)
import Foreign.Concurrent qualified as FC
import Network.Socket qualified as Net
import S2nTls.Error (Blocked (..), checkReturnWithBlocked, fromSysEither, fromSysError)
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
import S2nTls.Types (Config (..), Connection (..), Mode (..), TlsVersion (..))
import System.Posix.Types (Fd (..))
import UnliftIO (MonadIO, liftIO)
import UnliftIO.Foreign

{- | Create a new TLS connection.
The returned 'Connection' is automatically freed when garbage collected.
-}
newConnection :: (MonadIO m) => S2nTlsSys -> Mode -> m Connection
newConnection sys (Mode mode) = liftIO $ mask_ $ do
    result <- s2n_connection_new sys mode
    case result of
        Left err -> fromSysError sys err >>= throwIO
        Right ptr -> do
            readFdRef <- newIORef Nothing
            writeFdRef <- newIORef Nothing
            configRef <- newIORef Nothing
            certKeysRef <- newIORef []
            socketRef <- newIORef Nothing
            let
                finalize :: Ptr S2nConnection -> IO ()
                finalize p = do
                    _ <- s2n_connection_free sys p
                    -- assure all related resources are kept alive until the connection is fully freed
                    readIORef configRef >>= traverse_ touchForeignPtr
                    readIORef certKeysRef >>= traverse_ touchForeignPtr
            fptr <- FC.newForeignPtr ptr (finalize ptr)
            pure
                Connection
                    { connPtr = fptr
                    , connReadFd = readFdRef
                    , connWriteFd = writeFdRef
                    , connConfig = configRef
                    , connCertKeys = certKeysRef
                    , connSocket = socketRef
                    }

-- | Set the configuration for a connection.
setConnectionConfig :: (MonadIO m) => S2nTlsSys -> Connection -> Config -> m ()
setConnectionConfig sys conn config =
    liftIO $ do
        void $ withForeignPtr (connPtr conn) $ \cPtr ->
            withForeignPtr (configPtr config) $
                s2n_connection_set_config sys cPtr >=> fromSysEither sys
        -- Keep the config alive by storing a reference
        writeIORef (connConfig conn) (Just (configPtr config))

-- | Set both read and write file descriptors for the connection.
setFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setFd sys conn fd =
    liftIO $ do
        void $ withForeignPtr (connPtr conn) $ \cPtr ->
            s2n_connection_set_fd sys cPtr fd >>= fromSysEither sys
        writeIORef (connReadFd conn) (Just fd)
        writeIORef (connWriteFd conn) (Just fd)

-- | Set the read file descriptor for the connection.
setReadFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setReadFd sys conn fd =
    liftIO $ do
        void $ withForeignPtr (connPtr conn) $ \cPtr ->
            s2n_connection_set_read_fd sys cPtr fd >>= fromSysEither sys
        writeIORef (connReadFd conn) (Just fd)

-- | Set the write file descriptor for the connection.
setWriteFd :: (MonadIO m) => S2nTlsSys -> Connection -> CInt -> m ()
setWriteFd sys conn fd =
    liftIO $ do
        void $ withForeignPtr (connPtr conn) $ \cPtr ->
            s2n_connection_set_write_fd sys cPtr fd >>= fromSysEither sys
        writeIORef (connWriteFd conn) (Just fd)

{- | Set a socket for the connection.
This stores the socket reference to prevent it from being garbage collected,
extracts the file descriptor, and sets it on the connection.
-}
setSocket :: (MonadIO m) => S2nTlsSys -> Connection -> Net.Socket -> m ()
setSocket sys conn sock =
    liftIO $ do
        writeIORef (connSocket conn) (Just sock)
        fd <- Net.unsafeFdSocket sock
        void $ withForeignPtr (connPtr conn) $ \cPtr ->
            s2n_connection_set_fd sys cPtr fd >>= fromSysEither sys
        writeIORef (connReadFd conn) (Just fd)
        writeIORef (connWriteFd conn) (Just fd)

{- | Set the server name for SNI (Server Name Indication).
This should be called before 'negotiate' for client connections.
-}
setServerName :: (MonadIO m) => S2nTlsSys -> Connection -> String -> m ()
setServerName sys conn name =
    void $
        liftIO $
            withForeignPtr (connPtr conn) $ \cPtr ->
                withCString name $
                    s2n_set_server_name sys cPtr >=> fromSysEither sys

{- | Get the server name from the connection.
Returns 'Nothing' if no server name is set.
-}
getServerName :: (MonadIO m) => S2nTlsSys -> Connection -> m (Maybe String)
getServerName sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr -> do
            result <- s2n_get_server_name sys cPtr
            case result of
                Left _ -> pure Nothing
                Right namePtr ->
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
                checkReturnWithBlocked sys blockedPtr
                    =<< s2n_negotiate sys cPtr blockedPtr

{- | Send data over the TLS connection (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right bytesSent' with the number of bytes sent.
Note: Not all bytes may be sent in one call; use a loop to send all data.
-}
send :: (MonadIO m) => S2nTlsSys -> Connection -> ByteString -> m (Either Blocked Int)
send sys conn bs =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr ->
            alloca $ \blockedPtr -> do
                poke blockedPtr S2N_NOT_BLOCKED
                result <- BS.unsafeUseAsCStringLen bs $ \(ptr, len) -> do
                    s2n_send
                        sys
                        cPtr
                        (castPtr ptr)
                        (fromIntegral len)
                        blockedPtr
                blocked <- peek blockedPtr
                case result of
                    Right n -> pure (Right (fromIntegral n))
                    Left sysErr -> do
                        case toBlocked blocked of
                            Just b -> pure (Left b)
                            Nothing -> do
                                err <- fromSysError sys sysErr
                                throwIO err

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
                fptr <- BSI.mallocByteString maxLen
                result <- withForeignPtr fptr $ \ptr -> do
                    s2n_recv
                        sys
                        cPtr
                        (castPtr ptr)
                        (fromIntegral maxLen)
                        blockedPtr
                blocked <- peek blockedPtr
                case result of
                    Right n -> pure (Right (BSI.fromForeignPtr fptr 0 (fromIntegral n)))
                    Left sysErr -> do
                        case toBlocked blocked of
                            Just b -> pure (Left b)
                            Nothing -> do
                                err <- fromSysError sys sysErr
                                throwIO err

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
                checkReturnWithBlocked sys blockedPtr
                    =<< s2n_shutdown sys cPtr blockedPtr

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
                checkReturnWithBlocked sys blockedPtr
                    =<< s2n_shutdown_send sys cPtr blockedPtr

{- | Get the negotiated application protocol (ALPN).
Returns 'Nothing' if no application protocol was negotiated.
-}
getApplicationProtocol :: (MonadIO m) => S2nTlsSys -> Connection -> m (Maybe String)
getApplicationProtocol sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr -> do
            result <- s2n_get_application_protocol sys cPtr
            case result of
                Left _ -> pure Nothing
                Right protoPtr ->
                    if protoPtr == nullPtr
                        then pure Nothing
                        else Just <$> peekCString protoPtr

-- | Get the actual negotiated TLS protocol version.
getActualProtocolVersion :: (MonadIO m) => S2nTlsSys -> Connection -> m TlsVersion
getActualProtocolVersion sys conn = do
    version <-
        liftIO $
            withForeignPtr (connPtr conn) $
                s2n_connection_get_actual_protocol_version sys >=> fromSysEither sys
    pure (TlsVersion version)

-- | Get the negotiated cipher suite name.
getCipher :: (MonadIO m) => S2nTlsSys -> Connection -> m String
getCipher sys conn =
    liftIO $
        withForeignPtr (connPtr conn) $ \cPtr -> do
            result <- s2n_connection_get_cipher sys cPtr
            case result of
                Left _ -> pure ""
                Right cipherPtr ->
                    if cipherPtr == nullPtr
                        then pure ""
                        else peekCString cipherPtr

-- | Check if this connection is a resumed session.
isSessionResumed :: (MonadIO m) => S2nTlsSys -> Connection -> m Bool
isSessionResumed sys conn = do
    val <-
        liftIO $
            withForeignPtr (connPtr conn) $
                s2n_connection_is_session_resumed sys >=> fromSysEither sys
    pure (val /= 0)

{- | Wipe the connection for reuse.
This clears all connection state except the configuration.
-}
wipeConnection :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
wipeConnection sys conn =
    void $
        liftIO $
            withForeignPtr (connPtr conn) $
                s2n_connection_wipe sys >=> fromSysEither sys

{- | Free handshake-related memory after the handshake is complete.
This can reduce memory usage for long-lived connections.
-}
freeHandshake :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
freeHandshake sys conn =
    void $
        liftIO $
            withForeignPtr (connPtr conn) $
                s2n_connection_free_handshake sys >=> fromSysEither sys

-- | Release all buffers associated with the connection.
releaseBuffers :: (MonadIO m) => S2nTlsSys -> Connection -> m ()
releaseBuffers sys conn =
    void $
        liftIO $
            withForeignPtr (connPtr conn) $
                s2n_connection_release_buffers sys >=> fromSysEither sys

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

{- | Send all data over the TLS connection (blocking).
This function will block (using GHC's I/O manager) until all data
is sent or an error occurs.
Unlike 'blockingSend', this function loops until the entire 'ByteString'
has been transmitted.
-}
blockingSendAll :: (MonadIO m) => S2nTlsSys -> Connection -> ByteString -> m ()
blockingSendAll sys conn bs
    | BS.null bs = pure ()
    | otherwise = do
        n <- blockingSend sys conn bs
        blockingSendAll sys conn (BS.drop n bs)

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

{- | Wait on a blocked status using GHC's I/O manager.
Uses readfd/writefd in preference to fd.
-}
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
