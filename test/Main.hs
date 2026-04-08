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
import Control.Exception (bracket)
import Control.Monad (void)
import Data.ByteString qualified as BS
import Network.Socket qualified as Net
import S2nTls
import System.Directory (getCurrentDirectory)
import System.IO (Handle, hFlush, hGetLine, hPutStrLn)
import System.Process (
    CreateProcess (..),
    ProcessHandle,
    StdStream (..),
    createProcess,
    proc,
    terminateProcess,
    waitForProcess,
 )
import Test.Tasty (TestTree, defaultMain, testGroup)
import Test.Tasty.HUnit (assertBool, assertEqual, testCase)
import UnliftIO (timeout)

main :: IO ()
main =
    withS2nTls Linked $ \tls ->
        defaultMain (tests tls)

tests :: S2nTls IO -> TestTree
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
        ]

-- | Get the path to test certificates
getCertPath :: IO FilePath
getCertPath = do
    cwd <- getCurrentDirectory
    pure $ cwd ++ "/test/certs"

-- | Test client mode: connect to openssl s_server
testClientMode :: S2nTls IO -> IO ()
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
            result <- timeout 2000000 $ shutdownLoop tls conn
            case result of
                Nothing -> pure () -- Timeout is OK, openssl may not send close_notify
                Just _ -> pure ()

-- | Test server mode: accept connection from openssl s_client
testServerMode :: S2nTls IO -> IO ()
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

-- | Loop shutdown until complete
shutdownLoop :: S2nTls IO -> Connection -> IO ()
shutdownLoop tls conn = do
    result <- tls.shutdown conn
    case result of
        Right () -> pure ()
        Left BlockedOnRead -> do
            threadDelay 10000
            shutdownLoop tls conn
        Left BlockedOnWrite -> do
            threadDelay 10000
            shutdownLoop tls conn
        Left _ -> pure ()

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
