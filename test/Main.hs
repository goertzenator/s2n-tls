{-# LANGUAGE OverloadedRecordDot #-}
{-# LANGUAGE OverloadedStrings #-}

{- |
Module      : Main
Copyright   : (c) 2026
License     : BSD-3-Clause

Tests for s2n-tls bindings using OpenSSL s_server and s_client.
-}
module Main (main) where

import Control.Concurrent (forkIO, threadDelay)
import Control.Concurrent.Async (forConcurrently_)
import Control.Concurrent.MVar (newEmptyMVar, putMVar, takeMVar)
import Control.Exception (SomeException, bracket)
import Control.Exception qualified
import Control.Monad (replicateM_, void)
import Data.ByteString qualified as BS
import Data.IORef (modifyIORef', newIORef, readIORef, writeIORef)
import Network.Socket qualified as Net
import S2nTls
import System.Directory (getCurrentDirectory)
import System.IO (Handle, hFlush, hGetLine, hPutStrLn)
import System.Mem (performGC)
import System.Process (
    CreateProcess (..),
    ProcessHandle,
    StdStream (..),
    createProcess,
    proc,
    terminateProcess,
    waitForProcess,
 )
import System.Timeout (timeout)
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)
import Test.Tasty.QuickCheck (testProperty)
import Test.QuickCheck (Gen, Property, choose, forAll, ioProperty, vectorOf)

main :: IO ()
main =
    withS2nTls Linked $ \tls ->
        defaultMain (tests tls)

tests :: S2nTls -> TestTree
tests tls =
    testGroup
        "s2n-tls"
        [ testGroup
            "Client Mode"
            [ testCase "connect to openssl s_server and exchange data" (testClientMode tls)
            ]
        , testGroup
            "Server Mode"
            [ testCase "accept from openssl s_client and exchange data" (testServerMode tls)
            ]
        , testGroup
            "Session Tickets"
            [ testCase "session resumption with tickets" (testSessionTickets tls)
            ]
        , testGroup
            "GC Stress"
            [ testCase "session ticket callback survives GC" (testSessionTicketCallbackGC tls)
            , testCase "connection finalizer ordering" (testConnectionFinalizerOrdering tls)
            , testCase "heavy concurrent stress" (testHeavyConcurrentStress tls)
            ]
        , testGroup
            "QuickCheck"
            [ testProperty "bidirectional conversation" (propBidirectionalConversation tls)
            ]
        ]

-- | Get the path to test certificates
getCertPath :: IO FilePath
getCertPath = do
    cwd <- getCurrentDirectory
    pure $ cwd ++ "/test/certs"

-- | Test client mode: connect to openssl s_server
testClientMode :: S2nTls -> IO ()
testClientMode tls = do
    certPath <- getCertPath
    let certFile = certPath ++ "/cert.pem"
        keyFile = certPath ++ "/key.pem"

    -- Find a free port
    port <- findFreePort

    -- Start openssl s_server
    bracket (startOpenSSLServer certFile keyFile port) stopProcess $ \_ -> do
        -- Give the server time to start
        threadDelay 500000 -- 500ms

        -- Connect with s2n-tls client
        bracket (connectToServer "127.0.0.1" port) Net.close $ \sock -> do
            -- Create and configure connection
            config <- tls.newConfig
            tls.disableX509Verification config
            tls.setCipherPreferences config "default_tls13"

            conn <- tls.newConnection Client
            tls.setConnectionConfig conn config
            tls.setServerName conn "localhost"
            tls.setSocket conn sock

            -- Perform handshake
            tls.blockingNegotiate conn

            -- Send data
            let testData = "Hello from s2n-tls client!"
            tls.blockingSendAll conn (testData <> "\n")

            -- Receive response
            response <- tls.blockingRecv conn 1024
            assertBool "Should receive response" (not (BS.null response))
            assertEqual "Response should match" (BS.reverse testData <> "\n") response

            -- Shutdown
            result <- timeout 2000000 $ tls.blockingShutdown conn
            case result of
                Nothing -> pure () -- Timeout is OK, openssl may not send close_notify
                Just () -> pure ()

-- | Test server mode: accept connection from openssl s_client
testServerMode :: S2nTls -> IO ()
testServerMode tls = do
    certPath <- getCertPath
    let certFile = certPath ++ "/cert.pem"
        keyFile = certPath ++ "/key.pem"

    -- Read cert and key
    certPem <- BS.readFile certFile
    keyPem <- BS.readFile keyFile

    -- Find a free port
    port <- findFreePort

    let testData = "Hello from openssl s_client!"

    -- Create server socket
    bracket (createServerSocket port) Net.close $ \serverSock -> do
        -- Start openssl s_client in background
        _ <- forkIO $ do
            threadDelay 500000 -- 500ms to let server start listening
            bracket (startOpenSSLClient port) stopClientProcess $ \(mhin, mhout, _, _) -> do
                case (mhin, mhout) of
                    (Just hin, Just hout) -> do
                        -- Send data from client
                        hPutStrLn hin testData
                        hFlush hin
                        -- Read response
                        msg <- timeout 2000000 $ hGetLine hout
                        assertEqual "Client should receive response" (Just $ reverse testData) msg
                    _ -> error "startOpenSSLClient did not provide expected handles"

        -- Accept connection
        (clientSock, _) <- Net.accept serverSock

        -- Create and configure connection
        config <- tls.newConfig
        tls.setCipherPreferences config "default_tls13"

        -- Load certificate
        certKey <- tls.loadCertChainAndKeyPem certPem keyPem
        tls.addCertChainAndKeyToStore config certKey

        conn <- tls.newConnection Server
        tls.setConnectionConfig conn config
        tls.setSocket conn clientSock

        -- Perform handshake
        tls.blockingNegotiate conn

        putStrLn "Handshake complete, exchanging data..."
        -- Receive data from client
        received <- tls.blockingRecv conn 1024
        putStrLn $ "Received from client: " ++ show received
        assertBool "Should receive data from client" (not (BS.null received))

        -- Send response
        tls.blockingSendAll conn (((<> "\n") . BS.drop 1 . BS.reverse) received)
        putStrLn "Sent response to client"

        -- Cleanup
        Net.close clientSock

-- | Test session ticket resumption using s2n client and server
testSessionTickets :: S2nTls -> IO ()
testSessionTickets tls = do
    certPath <- getCertPath
    let certFile = certPath ++ "/cert.pem"
        keyFile = certPath ++ "/key.pem"

    -- Read cert and key
    certPem <- BS.readFile certFile
    keyPem <- BS.readFile keyFile

    -- Generate a ticket encryption key (32 random bytes - using deterministic for test)
    let ticketKey = BS.pack [1 .. 32]
        ticketKeyName = "test-key-1"

    -- IORef to store the session ticket from the first connection
    ticketRef <- newIORef Nothing

    -- Find a free port
    port <- findFreePort

    -- Create server config with session tickets enabled
    serverConfig <- tls.newConfig
    tls.setCipherPreferences serverConfig "default_tls13"
    certKey <- tls.loadCertChainAndKeyPem certPem keyPem
    tls.addCertChainAndKeyToStore serverConfig certKey
    tls.setSessionTicketsOnOff serverConfig True
    tls.addTicketCryptoKey serverConfig ticketKeyName ticketKey Nothing

    -- Create client config with session ticket callback
    clientConfig <- tls.newConfig
    tls.disableX509Verification clientConfig
    tls.setCipherPreferences clientConfig "default_tls13"
    tls.setSessionTicketsOnOff clientConfig True
    tls.setSessionTicketCallback clientConfig $ \ticketData _lifetime -> do
        writeIORef ticketRef (Just ticketData)

    -- Create server socket
    bracket (createServerSocket port) Net.close $ \serverSock -> do
        -- MVar to signal when server is ready for next connection
        serverReady <- newEmptyMVar

        -- Run server in background thread
        _ <- forkIO $ do
            -- First connection
            putMVar serverReady ()
            (clientSock1, _) <- Net.accept serverSock
            serverConn1 <- tls.newConnection Server
            tls.setConnectionConfig serverConn1 serverConfig
            tls.setSocket serverConn1 clientSock1
            tls.blockingNegotiate serverConn1
            received1 <- tls.blockingRecv serverConn1 1024
            tls.blockingSendAll serverConn1 received1
            Net.close clientSock1

            -- Second connection
            putMVar serverReady ()
            (clientSock2, _) <- Net.accept serverSock
            serverConn2 <- tls.newConnection Server
            tls.setConnectionConfig serverConn2 serverConfig
            tls.setSocket serverConn2 clientSock2
            tls.blockingNegotiate serverConn2
            received2 <- tls.blockingRecv serverConn2 1024
            tls.blockingSendAll serverConn2 received2
            Net.close clientSock2

        -- First client connection - establish and get ticket
        takeMVar serverReady
        threadDelay 100000 -- 100ms
        bracket (connectToServer "127.0.0.1" port) Net.close $ \sock1 -> do
            clientConn1 <- tls.newConnection Client
            tls.setConnectionConfig clientConn1 clientConfig
            tls.setServerName clientConn1 "localhost"
            tls.setSocket clientConn1 sock1
            tls.blockingNegotiate clientConn1

            -- First connection should NOT be resumed
            resumed1 <- tls.isSessionResumed clientConn1
            assertBool "First connection should not be resumed" (not resumed1)

            -- Exchange some data
            tls.blockingSendAll clientConn1 "ping"
            response1 <- tls.blockingRecv clientConn1 1024
            assertEqual "Should receive echo" "ping" response1

        -- Wait for ticket to be received (callback may be async)
        threadDelay 200000 -- 200ms

        -- Verify we got a ticket
        mTicket <- readIORef ticketRef
        assertBool "Should have received a session ticket" (mTicket /= Nothing)

        -- Second client connection - use the ticket
        takeMVar serverReady
        threadDelay 100000 -- 100ms
        bracket (connectToServer "127.0.0.1" port) Net.close $ \sock2 -> do
            clientConn2 <- tls.newConnection Client
            tls.setConnectionConfig clientConn2 clientConfig
            tls.setServerName clientConn2 "localhost"

            -- Set the session ticket for resumption
            case mTicket of
                Just ticket -> tls.setSession clientConn2 ticket
                Nothing -> error "No ticket available"

            tls.setSocket clientConn2 sock2
            tls.blockingNegotiate clientConn2

            -- Second connection SHOULD be resumed
            resumed2 <- tls.isSessionResumed clientConn2
            assertBool "Second connection should be resumed" resumed2

            -- Exchange some data to confirm connection works
            tls.blockingSendAll clientConn2 "pong"
            response2 <- tls.blockingRecv clientConn2 1024
            assertEqual "Should receive echo" "pong" response2

{- | Test that session ticket callbacks survive garbage collection.
This test exercises the FunPtr lifetime bug where the callback would be
freed by GC while C still holds a reference to it, causing a segfault.
-}
testSessionTicketCallbackGC :: S2nTls -> IO ()
testSessionTicketCallbackGC tls = do
    certPath <- getCertPath
    let certFile = certPath ++ "/cert.pem"
        keyFile = certPath ++ "/key.pem"

    -- Read cert and key
    certPem <- BS.readFile certFile
    keyPem <- BS.readFile keyFile

    -- Generate a ticket encryption key
    let ticketKey = BS.pack [1 .. 32]
        ticketKeyName = "test-key-gc"

    -- Track callback invocations
    callbackCountRef <- newIORef (0 :: Int)

    -- Find a free port
    port <- findFreePort

    -- Create server config with session tickets enabled
    serverConfig <- tls.newConfig
    tls.setCipherPreferences serverConfig "default_tls13"
    certKey <- tls.loadCertChainAndKeyPem certPem keyPem
    tls.addCertChainAndKeyToStore serverConfig certKey
    tls.setSessionTicketsOnOff serverConfig True
    tls.addTicketCryptoKey serverConfig ticketKeyName ticketKey Nothing

    -- Create client config with session ticket callback
    clientConfig <- tls.newConfig
    tls.disableX509Verification clientConfig
    tls.setCipherPreferences clientConfig "default_tls13"
    tls.setSessionTicketsOnOff clientConfig True
    tls.setSessionTicketCallback clientConfig $ \_ticketData _lifetime -> do
        -- Force GC inside the callback to stress test FunPtr lifetime
        performGC
        modifyIORef' callbackCountRef (+ 1)

    -- Force GC after setting up callback to try to collect the FunPtr
    performGC
    performGC

    -- Create server socket
    bracket (createServerSocket port) Net.close $ \serverSock -> do
        serverReady <- newEmptyMVar

        -- Run server in background
        _ <- forkIO $ do
            -- Perform multiple connections to stress test GC
            replicateM_ 3 $ do
                putMVar serverReady ()
                (clientSock, _) <- Net.accept serverSock
                serverConn <- tls.newConnection Server
                tls.setConnectionConfig serverConn serverConfig
                tls.setSocket serverConn clientSock
                tls.blockingNegotiate serverConn
                _ <- tls.blockingRecv serverConn 1024
                tls.blockingSendAll serverConn "ok"
                -- Force GC on server side too
                performGC
                Net.close clientSock

        -- Make multiple connections, forcing GC between each
        replicateM_ 3 $ do
            takeMVar serverReady
            threadDelay 100000

            -- Force GC before connecting
            performGC

            bracket (connectToServer "127.0.0.1" port) Net.close $ \sock -> do
                clientConn <- tls.newConnection Client
                tls.setConnectionConfig clientConn clientConfig
                tls.setServerName clientConn "localhost"
                tls.setSocket clientConn sock
                tls.blockingNegotiate clientConn
                tls.blockingSendAll clientConn "test"
                _ <- tls.blockingRecv clientConn 1024

                -- Force GC while connection is active
                performGC
                performGC

            -- Force GC after connection is closed
            performGC

        -- Wait a bit for callbacks to fire
        threadDelay 300000
        performGC

        -- Verify callbacks were invoked (if we got here without segfault, test passed)
        callbackCount <- readIORef callbackCountRef
        assertBool
            ("Session ticket callbacks should have been invoked, got " ++ show callbackCount)
            (callbackCount > 0)

{- | Test that connection finalizers properly keep config alive during cleanup.
This exercises the bug where touchForeignPtr was called AFTER s2n_connection_free,
causing use-after-free when the config was finalized before the connection.
-}
testConnectionFinalizerOrdering :: S2nTls -> IO ()
testConnectionFinalizerOrdering tls = do
    certPath <- getCertPath
    let certFile = certPath ++ "/cert.pem"
        keyFile = certPath ++ "/key.pem"

    certPem <- BS.readFile certFile
    keyPem <- BS.readFile keyFile

    -- Create many short-lived connections with shared config
    -- to stress the finalizer ordering
    replicateM_ 50 $ do
        -- Create config (will be finalized when this iteration ends)
        config <- tls.newConfig
        tls.setCipherPreferences config "default_tls13"
        certKey <- tls.loadCertChainAndKeyPem certPem keyPem
        tls.addCertChainAndKeyToStore config certKey

        -- Create connections that reference the config
        replicateM_ 5 $ do
            conn <- tls.newConnection Server
            tls.setConnectionConfig conn config
            -- Let connection go out of scope
            performGC

        -- Force GC to finalize connections while config might also be finalizing
        performGC
        performGC

    -- If we get here without segfault, the test passed
    assertBool "Survived connection/config finalization" True

{- | Heavy concurrent stress test.
Creates many configs and connections concurrently with aggressive GC.
This may trigger profiling-related crashes.
-}
testHeavyConcurrentStress :: S2nTls -> IO ()
testHeavyConcurrentStress tls = do
    certPath <- getCertPath
    let certFile = certPath ++ "/cert.pem"
        keyFile = certPath ++ "/key.pem"

    certPem <- BS.readFile certFile
    keyPem <- BS.readFile keyFile

    -- Run many iterations with concurrent threads
    replicateM_ 10 $ do
        -- Create 8 concurrent threads, each creating configs and connections
        forConcurrently_ [1 .. 8 :: Int] $ \_ -> do
            replicateM_ 10 $ do
                -- Create config
                config <- tls.newConfig
                tls.setCipherPreferences config "default_tls13"
                certKey <- tls.loadCertChainAndKeyPem certPem keyPem
                tls.addCertChainAndKeyToStore config certKey

                -- Create connections
                replicateM_ 5 $ do
                    conn <- tls.newConnection Server
                    tls.setConnectionConfig conn config
                    performGC

                performGC

        -- Force major GC between rounds
        performGC
        performGC

    assertBool "Survived heavy concurrent stress" True

-- | Find a free port
findFreePort :: IO Int
findFreePort = do
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.bind sock (Net.SockAddrInet 0 (Net.tupleToHostAddress (127, 0, 0, 1)))
    Net.listen sock 1
    port <- Net.socketPort sock
    Net.close sock
    pure (fromIntegral port)

-- | Connect to a server
connectToServer :: String -> Int -> IO Net.Socket
connectToServer host port = do
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    let hints = Net.defaultHints{Net.addrSocketType = Net.Stream}
    addr : _ <- Net.getAddrInfo (Just hints) (Just host) (Just (show port))
    Net.connect sock (Net.addrAddress addr)
    pure sock

-- | Create a server socket
createServerSocket :: Int -> IO Net.Socket
createServerSocket port = do
    sock <- Net.socket Net.AF_INET Net.Stream Net.defaultProtocol
    Net.setSocketOption sock Net.ReuseAddr 1
    Net.bind sock (Net.SockAddrInet (fromIntegral port) (Net.tupleToHostAddress (127, 0, 0, 1)))
    Net.listen sock 5
    pure sock

-- | Start openssl s_server
startOpenSSLServer :: FilePath -> FilePath -> Int -> IO ProcessHandle
startOpenSSLServer certFile keyFile port = do
    (_, _, _, ph) <-
        createProcess
            (proc "openssl" ["s_server", "-cert", certFile, "-key", keyFile, "-accept", show port, "-quiet", "-rev"])
                { std_in = CreatePipe
                , std_out = CreatePipe
                , std_err = Inherit
                }
    pure ph

-- | Start openssl s_client
startOpenSSLClient :: Int -> IO (Maybe Handle, Maybe Handle, Maybe Handle, ProcessHandle)
startOpenSSLClient port = do
    createProcess
        (proc "openssl" ["s_client", "-connect", "127.0.0.1:" ++ show port, "-quiet", "-no_ign_eof"])
            { std_in = CreatePipe
            , std_out = CreatePipe
            , std_err = Inherit
            }

-- | Stop a process
stopProcess :: ProcessHandle -> IO ()
stopProcess ph = do
    terminateProcess ph
    void $ waitForProcess ph

-- | Stop a client process (from createProcess tuple)
stopClientProcess :: (Maybe Handle, Maybe Handle, Maybe Handle, ProcessHandle) -> IO ()
stopClientProcess (_, _, _, ph) = stopProcess ph

-- | Generate a random message (non-empty ByteString of printable ASCII)
genMessage :: Gen BS.ByteString
genMessage = do
    len <- choose (1, 1000)
    bytes <- vectorOf len (choose (32, 126)) -- printable ASCII
    pure $ BS.pack (map fromIntegral (bytes :: [Int]))

-- | Generate a conversation: list of (direction, message) pairs
-- direction: True = client sends, False = server sends
genConversation :: Gen [(Bool, BS.ByteString)]
genConversation = do
    numExchanges <- choose (10 :: Int, 50)
    sequence [genExchange | _ <- [1..numExchanges]]
  where
    genExchange = do
        direction <- choose (False, True)
        msg <- genMessage
        pure (direction, msg)

{- | QuickCheck property: bidirectional conversation with GC stress.
This test creates a client-server pair and exchanges many random messages
in both directions, with periodic GC to stress finalizers.
-}
propBidirectionalConversation :: S2nTls -> Property
propBidirectionalConversation tls = forAll genConversation $ \conversation ->
    ioProperty $ do
        certPath <- getCertPath
        let certFile = certPath ++ "/cert.pem"
            keyFile = certPath ++ "/key.pem"

        certPem <- BS.readFile certFile
        keyPem <- BS.readFile keyFile

        port <- findFreePort

        -- Create server config
        serverConfig <- tls.newConfig
        tls.setCipherPreferences serverConfig "default_tls13"
        certKey <- tls.loadCertChainAndKeyPem certPem keyPem
        tls.addCertChainAndKeyToStore serverConfig certKey

        -- Create client config
        clientConfig <- tls.newConfig
        tls.disableX509Verification clientConfig
        tls.setCipherPreferences clientConfig "default_tls13"

        -- Track received messages for verification
        serverReceivedRef <- newIORef []
        clientReceivedRef <- newIORef []
        errorRef <- newIORef Nothing

        bracket (createServerSocket port) Net.close $ \serverSock -> do
            serverReady <- newEmptyMVar
            serverDone <- newEmptyMVar

            -- Server thread
            _ <- forkIO $ do
                putMVar serverReady ()
                (clientSock, _) <- Net.accept serverSock
                serverConn <- tls.newConnection Server
                tls.setConnectionConfig serverConn serverConfig
                tls.setSocket serverConn clientSock

                tls.blockingNegotiate serverConn

                -- Process conversation from server's perspective
                let serverLoop [] = pure ()
                    serverLoop ((isClientSend, msg) : rest) = do
                        performGC -- Stress GC during conversation
                        if isClientSend
                            then do
                                -- Server receives
                                received <- tls.blockingRecv serverConn (BS.length msg + 100)
                                modifyIORef' serverReceivedRef (received :)
                                serverLoop rest
                            else do
                                -- Server sends
                                tls.blockingSendAll serverConn msg
                                serverLoop rest

                serverLoop conversation `Control.Exception.catch` \(e :: SomeException) ->
                    writeIORef errorRef (Just $ "Server error: " ++ show e)

                Net.close clientSock
                putMVar serverDone ()

            -- Client
            takeMVar serverReady
            threadDelay 50000

            bracket (connectToServer "127.0.0.1" port) Net.close $ \sock -> do
                clientConn <- tls.newConnection Client
                tls.setConnectionConfig clientConn clientConfig
                tls.setServerName clientConn "localhost"
                tls.setSocket clientConn sock

                tls.blockingNegotiate clientConn

                -- Process conversation from client's perspective
                let clientLoop [] = pure ()
                    clientLoop ((isClientSend, msg) : rest) = do
                        performGC -- Stress GC during conversation
                        if isClientSend
                            then do
                                -- Client sends
                                tls.blockingSendAll clientConn msg
                                clientLoop rest
                            else do
                                -- Client receives
                                received <- tls.blockingRecv clientConn (BS.length msg + 100)
                                modifyIORef' clientReceivedRef (received :)
                                clientLoop rest

                clientLoop conversation `Control.Exception.catch` \(e :: SomeException) ->
                    writeIORef errorRef (Just $ "Client error: " ++ show e)

            takeMVar serverDone
            performGC

            -- Check for errors
            mErr <- readIORef errorRef
            case mErr of
                Just err -> error err
                Nothing -> do
                    -- Verify messages match
                    serverReceived <- reverse <$> readIORef serverReceivedRef
                    clientReceived <- reverse <$> readIORef clientReceivedRef

                    let expectedServerReceived = [msg | (True, msg) <- conversation]
                        expectedClientReceived = [msg | (False, msg) <- conversation]

                    pure $ serverReceived == expectedServerReceived
                        && clientReceived == expectedClientReceived
