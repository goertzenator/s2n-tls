{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : S2nTls.Connection
Copyright   : (c) 2026
License     : BSD-3-Clause
Maintainer  : daniel.goertzen@gmail.com

This module provides functions for creating, configuring, and using
TLS connections. All I/O operations return @'Either' t'S2nTls.Ffi.Types.S2nBlockedStatus' a@ to handle
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
    blockingShutdown,
    blockingShutdownSend,

    -- * Connection Info
    getApplicationProtocol,
    getActualProtocolVersion,
    getCipher,
    isSessionResumed,

    -- * Session Resumption
    setSession,

    -- * Connection Management
    wipeConnection,
    freeHandshake,
    releaseBuffers,
) where

import Control.Concurrent (threadWaitRead, threadWaitWrite)
import Control.Exception (mask_, throwIO)
import Control.Monad (void, (>=>))
import Control.Monad.Primitive
import Data.ByteString (ByteString)
import Data.ByteString qualified as BS
import Data.ByteString.Internal qualified as BSI
import Data.ByteString.Unsafe qualified as BS
import Data.IORef (newIORef, readIORef, writeIORef)
import Foreign hiding (void)
import Foreign.C.String (peekCString, withCString)
import Foreign.C.Types (CInt)
import Foreign.Concurrent qualified as FC
import Network.Socket qualified as Net
import S2nTls.Error (checkReturnWithBlocked, fromFfiEither)
import S2nTls.Ffi.Types (
    S2nBlockedStatus (..),
    S2nConnection,
    S2nTlsFfi (..),
    pattern S2nBlockedOnApplicationInput,
    pattern S2nBlockedOnEarlyData,
    pattern S2nBlockedOnRead,
    pattern S2nBlockedOnWrite,
    pattern S2nNotBlocked,
    pattern S2nSelfServiceBlinding,
 )
import S2nTls.Types (Config (..), Connection (..), Mode (..), TlsVersion (..))
import System.Posix.Types (Fd (..))

{- | Create a new TLS connection.
The returned t'Connection' is automatically freed when garbage collected.
Disable built in blinding because it can cause significant
blocking on the order of 10 sec. Blinding mitigates Lucky13
timing attacks on CBC ciphers. TLS 1.3 no longer has CBC
ciphers.  See s2n documentation regarding self-service blinding
if you require it.
-}
newConnection :: S2nTlsFfi -> Mode -> IO Connection
newConnection ffi (Mode mode) = mask_ $ do
    result <- s2n_connection_new ffi mode

    case result of
        Left err -> throwIO err
        Right ptr -> do
            readFdRef <- newIORef Nothing
            writeFdRef <- newIORef Nothing
            configRef <- newIORef Nothing
            -- certKeysRef <- newIORef []
            socketRef <- newIORef Nothing
            let
                finalize :: Ptr S2nConnection -> IO ()
                finalize p = do
                    -- Read contents of IORefs - we need to keep the actual
                    -- ForeignPtrs/Socket alive, not just the IORefs themselves
                    cfg <- readIORef configRef
                    -- certs <- readIORef certKeysRef
                    sock <- readIORef socketRef
                    -- Keep contents alive during s2n_connection_free
                    void $ keepAlive (cfg, sock) $ do
                        s2n_connection_free ffi p

            fptr <- FC.newForeignPtr ptr (finalize ptr)

            void $
                s2n_connection_set_blinding ffi ptr S2nSelfServiceBlinding
                    >>= fromFfiEither

            pure
                Connection
                    { connPtr = fptr
                    , connReadFd = readFdRef
                    , connWriteFd = writeFdRef
                    , connConfig = configRef
                    , -- , connCertKeys = certKeysRef
                      connSocket = socketRef
                    }

-- | Set the configuration for a connection.
setConnectionConfig :: S2nTlsFfi -> Connection -> Config -> IO ()
setConnectionConfig ffi conn config = mask_ $ do
    void $ withForeignPtr (connPtr conn) $ \cPtr ->
        withForeignPtr (configPtr config) $
            s2n_connection_set_config ffi cPtr >=> fromFfiEither
    -- Keep the config alive by storing a reference
    writeIORef (connConfig conn) (Just (configPtr config))

-- | Set both read and write file descriptors for the connection.
setFd :: S2nTlsFfi -> Connection -> CInt -> IO ()
setFd ffi conn fd = mask_ $ do
    void $ withForeignPtr (connPtr conn) $ \cPtr ->
        s2n_connection_set_fd ffi cPtr fd >>= fromFfiEither
    writeIORef (connReadFd conn) (Just fd)
    writeIORef (connWriteFd conn) (Just fd)

-- | Set the read file descriptor for the connection.
setReadFd :: S2nTlsFfi -> Connection -> CInt -> IO ()
setReadFd ffi conn fd = mask_ $ do
    void $ withForeignPtr (connPtr conn) $ \cPtr ->
        s2n_connection_set_read_fd ffi cPtr fd >>= fromFfiEither
    writeIORef (connReadFd conn) (Just fd)

-- | Set the write file descriptor for the connection.
setWriteFd :: S2nTlsFfi -> Connection -> CInt -> IO ()
setWriteFd ffi conn fd = mask_ $ do
    void $ withForeignPtr (connPtr conn) $ \cPtr ->
        s2n_connection_set_write_fd ffi cPtr fd >>= fromFfiEither
    writeIORef (connWriteFd conn) (Just fd)

{- | Set a socket for the connection.
This stores the socket reference to prevent it from being garbage collected,
extracts the file descriptor, and sets it on the connection.
-}
setSocket :: S2nTlsFfi -> Connection -> Net.Socket -> IO ()
setSocket ffi conn sock = mask_ $ do
    writeIORef (connSocket conn) (Just sock)
    fd <- Net.unsafeFdSocket sock
    void $ withForeignPtr (connPtr conn) $ \cPtr ->
        s2n_connection_set_fd ffi cPtr fd >>= fromFfiEither
    writeIORef (connReadFd conn) (Just fd)
    writeIORef (connWriteFd conn) (Just fd)

{- | Set the server name for SNI (Server Name Indication).
This should be called before 'negotiate' for client connections.
-}
setServerName :: S2nTlsFfi -> Connection -> String -> IO ()
setServerName ffi conn name =
    void $
        withForeignPtr (connPtr conn) $ \cPtr ->
            withCString name $
                s2n_set_server_name ffi cPtr >=> fromFfiEither

{- | Get the server name from the connection.
Returns 'Nothing' if no server name is set.
-}
getServerName :: S2nTlsFfi -> Connection -> IO (Maybe String)
getServerName ffi conn =
    withForeignPtr (connPtr conn) $ \cPtr -> do
        result <- s2n_get_server_name ffi cPtr
        case result of
            Left _ -> pure Nothing
            Right namePtr ->
                if namePtr == nullPtr
                    then pure Nothing
                    else Just <$> peekCString namePtr

{- | Perform the TLS handshake (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
Throws t'S2nTls.Ffi.Types.S2nError' on protocol errors or other failures.
-}
negotiate :: S2nTlsFfi -> Connection -> IO (Either S2nBlockedStatus ())
negotiate ffi conn =
    withForeignPtr (connPtr conn) $ \cPtr ->
        alloca $ \blockedPtr -> do
            poke blockedPtr S2nNotBlocked
            fmap void . checkReturnWithBlocked ffi blockedPtr
                =<< s2n_negotiate ffi cPtr blockedPtr

{- | Send data over the TLS connection (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right bytesSent' with the number of bytes sent.
Note: Not all bytes may be sent in one call; use a loop to send all data.
-}
send :: S2nTlsFfi -> Connection -> ByteString -> IO (Either S2nBlockedStatus Int)
send ffi conn bs =
    withForeignPtr (connPtr conn) $ \cPtr ->
        alloca $ \blockedPtr -> do
            poke blockedPtr S2nNotBlocked
            result <- BS.unsafeUseAsCStringLen bs $ \(ptr, len) -> do
                s2n_send
                    ffi
                    cPtr
                    (castPtr ptr)
                    (fromIntegral len)
                    blockedPtr
            fmap fromIntegral <$> checkReturnWithBlocked ffi blockedPtr result

{- | Receive data from the TLS connection (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right bytes' with the received data.
Returns an empty 'ByteString' if the connection was closed cleanly.
-}
recv :: S2nTlsFfi -> Connection -> Int -> IO (Either S2nBlockedStatus ByteString)
recv ffi conn maxLen =
    withForeignPtr (connPtr conn) $ \cPtr ->
        alloca $ \blockedPtr -> do
            poke blockedPtr S2nNotBlocked
            fptr <- BSI.mallocByteString maxLen
            result <- withForeignPtr fptr $ \ptr -> do
                s2n_recv
                    ffi
                    cPtr
                    (castPtr ptr)
                    (fromIntegral maxLen)
                    blockedPtr
            fmap (\n -> BSI.fromForeignPtr fptr 0 (fromIntegral n))
                <$> checkReturnWithBlocked ffi blockedPtr result

{- | Shutdown the TLS connection (bidirectional, non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
-}
shutdown :: S2nTlsFfi -> Connection -> IO (Either S2nBlockedStatus ())
shutdown ffi conn =
    withForeignPtr (connPtr conn) $ \cPtr ->
        alloca $ \blockedPtr -> do
            poke blockedPtr S2nNotBlocked
            fmap void . checkReturnWithBlocked ffi blockedPtr
                =<< s2n_shutdown ffi cPtr blockedPtr

{- | Shutdown only the send side of the TLS connection (non-blocking).
Returns 'Left blocked' if the operation would block on I/O.
On success, returns 'Right ()'.
-}
shutdownSend :: S2nTlsFfi -> Connection -> IO (Either S2nBlockedStatus ())
shutdownSend ffi conn =
    withForeignPtr (connPtr conn) $ \cPtr ->
        alloca $ \blockedPtr -> do
            poke blockedPtr S2nNotBlocked
            fmap void . checkReturnWithBlocked ffi blockedPtr
                =<< s2n_shutdown_send ffi cPtr blockedPtr

{- | Get the negotiated application protocol (ALPN).
Returns 'Nothing' if no application protocol was negotiated.
-}
getApplicationProtocol :: S2nTlsFfi -> Connection -> IO (Maybe String)
getApplicationProtocol ffi conn =
    withForeignPtr (connPtr conn) $ \cPtr -> do
        result <- s2n_get_application_protocol ffi cPtr
        case result of
            Left _ -> pure Nothing
            Right protoPtr ->
                if protoPtr == nullPtr
                    then pure Nothing
                    else Just <$> peekCString protoPtr

-- | Get the actual negotiated TLS protocol version.
getActualProtocolVersion :: S2nTlsFfi -> Connection -> IO TlsVersion
getActualProtocolVersion ffi conn = do
    version <-
        withForeignPtr (connPtr conn) $
            s2n_connection_get_actual_protocol_version ffi >=> fromFfiEither
    pure (TlsVersion version)

-- | Get the negotiated cipher suite name.
getCipher :: S2nTlsFfi -> Connection -> IO String
getCipher ffi conn =
    withForeignPtr (connPtr conn) $ \cPtr -> do
        result <- s2n_connection_get_cipher ffi cPtr
        case result of
            Left _ -> pure ""
            Right cipherPtr ->
                if cipherPtr == nullPtr
                    then pure ""
                    else peekCString cipherPtr

-- | Check if this connection is a resumed session.
isSessionResumed :: S2nTlsFfi -> Connection -> IO Bool
isSessionResumed ffi conn = do
    val <-
        withForeignPtr (connPtr conn) $
            s2n_connection_is_session_resumed ffi >=> fromFfiEither
    pure (val /= 0)

{- | Set session data for resumption.

This should be called before 'negotiate' on a client connection to attempt
session resumption. The session data should be the ticket data received via
the callback registered via 'S2nTls.Config.setSessionTicketCallback' from a previous connection to the same server.
-}
setSession :: S2nTlsFfi -> Connection -> ByteString -> IO ()
setSession ffi conn sessionData =
    void $
        withForeignPtr (connPtr conn) $ \cPtr ->
            BS.unsafeUseAsCStringLen sessionData $ \(ptr, len) ->
                s2n_connection_set_session ffi cPtr (castPtr ptr) (fromIntegral len)
                    >>= fromFfiEither

{- | Wipe the connection for reuse.
This clears all connection state except the configuration.
-}
wipeConnection :: S2nTlsFfi -> Connection -> IO ()
wipeConnection ffi conn =
    void $
        withForeignPtr (connPtr conn) $
            s2n_connection_wipe ffi >=> fromFfiEither

{- | Free handshake-related memory after the handshake is complete.
This can reduce memory usage for long-lived connections.
-}
freeHandshake :: S2nTlsFfi -> Connection -> IO ()
freeHandshake ffi conn =
    void $
        withForeignPtr (connPtr conn) $
            s2n_connection_free_handshake ffi >=> fromFfiEither

-- | Release all buffers associated with the connection.
releaseBuffers :: S2nTlsFfi -> Connection -> IO ()
releaseBuffers ffi conn =
    void $
        withForeignPtr (connPtr conn) $
            s2n_connection_release_buffers ffi >=> fromFfiEither

{- | Perform the TLS handshake (blocking).
This function will block (using GHC's I/O manager) until the handshake
completes or an error occurs.
Throws t'S2nTls.Ffi.Types.S2nError' on protocol errors or other failures.
-}
blockingNegotiate :: S2nTlsFfi -> Connection -> IO ()
blockingNegotiate ffi conn = go
  where
    go = do
        result <- negotiate ffi conn
        case result of
            Right () -> pure ()
            Left blocked -> do
                waitOnBlocked conn blocked
                go

{- | Send data over the TLS connection (blocking).
This function will block (using GHC's I/O manager) until the data
is sent or an error occurs.
Returns the number of bytes sent.
Note: Not all bytes may be sent in one call; use a loop to send all data.
-}
blockingSend :: S2nTlsFfi -> Connection -> ByteString -> IO Int
blockingSend ffi conn bs = go
  where
    go = do
        result <- send ffi conn bs
        case result of
            Right n -> pure n
            Left blocked -> do
                waitOnBlocked conn blocked
                go

{- | Send all data over the TLS connection (blocking).
This function will block (using GHC's I/O manager) until all data
is sent or an error occurs.
Unlike 'blockingSend', this function loops until the entire 'ByteString'
has been transmitted.
-}
blockingSendAll :: S2nTlsFfi -> Connection -> ByteString -> IO ()
blockingSendAll ffi conn bs
    | BS.null bs = pure ()
    | otherwise = do
        n <- blockingSend ffi conn bs
        blockingSendAll ffi conn (BS.drop n bs)

{- | Receive data from the TLS connection (blocking).
This function will block (using GHC's I/O manager) until data is
available or an error occurs.
Returns the received data, or an empty 'ByteString' if the connection
was closed cleanly.
-}
blockingRecv :: S2nTlsFfi -> Connection -> Int -> IO ByteString
blockingRecv ffi conn maxLen = go
  where
    go = do
        result <- recv ffi conn maxLen
        case result of
            Right bs -> pure bs
            Left blocked -> do
                waitOnBlocked conn blocked
                go

{- | Shutdown the TLS connection (bidirectional, blocking).
This function will block (using GHC's I/O manager) until the shutdown
completes or an error occurs.
Throws t'S2nTls.Ffi.Types.S2nError' on protocol errors or other failures.
-}
blockingShutdown :: S2nTlsFfi -> Connection -> IO ()
blockingShutdown ffi conn = go
  where
    go = do
        result <- shutdown ffi conn
        case result of
            Right () -> pure ()
            Left blocked -> do
                putStrLn $ "blockingShutdown: " <> show blocked
                waitOnBlocked conn blocked
                putStrLn "blockingShutdown unblocked"
                go

{- | Shutdown only the send side of the TLS connection (blocking).
This function will block (using GHC's I/O manager) until the shutdown
completes or an error occurs.
Throws t'S2nTls.Ffi.Types.S2nError' on protocol errors or other failures.
-}
blockingShutdownSend :: S2nTlsFfi -> Connection -> IO ()
blockingShutdownSend ffi conn = go
  where
    go = do
        result <- shutdownSend ffi conn
        case result of
            Right () -> pure ()
            Left blocked -> do
                waitOnBlocked conn blocked
                go

{- | Wait on a blocked status using GHC's I/O manager.
Uses readfd/writefd in preference to fd.
-}
waitOnBlocked :: Connection -> S2nBlockedStatus -> IO ()
waitOnBlocked conn blocked = case blocked of
    S2nBlockedOnRead -> do
        mFd <- getReadFd conn
        case mFd of
            Just fd -> threadWaitRead (Fd fd)
            Nothing -> pure () -- No fd set, just return
    S2nBlockedOnWrite -> do
        mFd <- getWriteFd conn
        case mFd of
            Just fd -> threadWaitWrite (Fd fd)
            Nothing -> pure () -- No fd set, just return
    S2nBlockedOnApplicationInput -> pure () -- Can't wait on this
    S2nBlockedOnEarlyData -> pure () -- Can't wait on this
    _ -> pure () -- Unknown/not-blocked: shouldn't happen here

-- | Get the read file descriptor.
getReadFd :: Connection -> IO (Maybe CInt)
getReadFd conn = readIORef (connReadFd conn)

-- | Get the write file descriptor.
getWriteFd :: Connection -> IO (Maybe CInt)
getWriteFd conn = readIORef (connWriteFd conn)
