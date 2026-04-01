-- |
-- Module      : S2nTls.Error
-- Copyright   : (c) 2025
-- License     : BSD-3-Clause
-- Maintainer  : your.email@example.com
-- Stability   : experimental
-- Portability : non-portable (requires s2n-tls C library)
--
{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : S2nTls.Error
Description : Error types and exception handling for s2n-tls
License     : BSD-3-Clause

This module provides Haskell-idiomatic error handling for s2n-tls operations.
Truly exceptional errors (internal errors, usage errors, protocol violations)
are thrown as exceptions. Expected "errors" like blocking on I/O are returned
via 'Either'.
-}
module S2nTls.Error (
  -- * Exceptions
  S2nError (..),
  S2nErrorType (..),
  throwS2nError,

  -- * Blocking Status
  Blocked (..),

  -- * Internal Utilities
  checkReturn,
  checkReturnWithBlocked,
  getLastError,
) where

import Foreign.C.Types (CInt (..))
import S2nTls.Sys.Types (
  S2nBlockedStatus (..),
  S2nTlsSys (..),
  pattern S2N_BLOCKED_ON_APPLICATION_INPUT,
  pattern S2N_BLOCKED_ON_EARLY_DATA,
  pattern S2N_BLOCKED_ON_READ,
  pattern S2N_BLOCKED_ON_WRITE,
  pattern S2N_CALLBACK_BLOCKED,
  pattern S2N_ERR_T_ALERT,
  pattern S2N_ERR_T_BLOCKED,
  pattern S2N_ERR_T_CLOSED,
  pattern S2N_ERR_T_INTERNAL,
  pattern S2N_ERR_T_IO,
  pattern S2N_ERR_T_OK,
  pattern S2N_ERR_T_PROTO,
  pattern S2N_ERR_T_USAGE,
  pattern S2N_FAILURE,
  pattern S2N_NOT_BLOCKED,
  pattern S2N_SUCCESS,
 )
import S2nTls.Sys.Types qualified as Sys
import UnliftIO (Exception, MonadIO, liftIO, throwIO)
import UnliftIO.Foreign (Ptr, nullPtr, peek, peekCString)

-- | Classification of s2n errors.
data S2nErrorType
  = -- | No error
    ErrorOk
  | -- | I/O error (check errno)
    ErrorIO
  | -- | Connection was closed
    ErrorClosed
  | -- | Operation would block
    ErrorBlocked
  | -- | TLS alert received
    ErrorAlert
  | -- | Protocol error
    ErrorProtocol
  | -- | Internal library error
    ErrorInternal
  | -- | API usage error
    ErrorUsage
  deriving (Eq, Show)

-- | Convert from the sys-level error type
fromSysErrorType :: Sys.S2nErrorType -> S2nErrorType
fromSysErrorType t = case t of
  S2N_ERR_T_OK -> ErrorOk
  S2N_ERR_T_IO -> ErrorIO
  S2N_ERR_T_CLOSED -> ErrorClosed
  S2N_ERR_T_BLOCKED -> ErrorBlocked
  S2N_ERR_T_ALERT -> ErrorAlert
  S2N_ERR_T_PROTO -> ErrorProtocol
  S2N_ERR_T_INTERNAL -> ErrorInternal
  S2N_ERR_T_USAGE -> ErrorUsage
  _ -> ErrorInternal

-- | An exception representing an s2n-tls error.
data S2nError = S2nError
  { s2nErrorType :: !S2nErrorType
  -- ^ The type/category of error
  , s2nErrorCode :: !CInt
  -- ^ The raw error code
  , s2nErrorMessage :: !String
  -- ^ Human-readable error message
  , s2nErrorDebug :: !(Maybe String)
  -- ^ Debug information (if available)
  }
  deriving (Eq, Show)

instance Exception S2nError

-- | Status indicating why an operation blocked.
data Blocked
  = -- | Blocked waiting for data to read
    BlockedOnRead
  | -- | Blocked waiting to write data
    BlockedOnWrite
  | -- | Blocked waiting for application input
    BlockedOnApplicationInput
  | -- | Blocked on early data
    BlockedOnEarlyData
  deriving (Eq, Show)

-- | Convert from the sys-level blocked status
fromSysBlockedStatus :: S2nBlockedStatus -> Maybe Blocked
fromSysBlockedStatus s = case s of
  S2N_NOT_BLOCKED -> Nothing
  S2N_BLOCKED_ON_READ -> Just BlockedOnRead
  S2N_BLOCKED_ON_WRITE -> Just BlockedOnWrite
  S2N_BLOCKED_ON_APPLICATION_INPUT -> Just BlockedOnApplicationInput
  S2N_BLOCKED_ON_EARLY_DATA -> Just BlockedOnEarlyData
  _ -> Nothing

-- | Get the last error information from the s2n library.
getLastError :: (MonadIO m) => S2nTlsSys -> m S2nError
getLastError sys = do
  errnoPtr <- liftIO $ s2n_errno_location sys
  errCode <- liftIO $ peek errnoPtr
  errTypeRaw <- liftIO $ s2n_error_get_type sys errCode
  let errType = fromSysErrorType errTypeRaw
  msgPtr <- liftIO $ s2n_strerror sys errCode nullPtr
  msg <-
    if msgPtr == nullPtr
      then pure "Unknown error"
      else peekCString msgPtr
  debugPtr <- liftIO $ s2n_strerror_debug sys errCode nullPtr
  debugMsg <-
    if debugPtr == nullPtr
      then pure Nothing
      else Just <$> peekCString debugPtr
  pure
    S2nError
      { s2nErrorType = errType
      , s2nErrorCode = errCode
      , s2nErrorMessage = msg
      , s2nErrorDebug = debugMsg
      }

-- | Throw an S2nError exception with current error state.
throwS2nError :: (MonadIO m) => S2nTlsSys -> m a
throwS2nError sys = do
  err <- getLastError sys
  throwIO err

{- | Check the return value of an s2n function and throw on failure.
Use this for functions that should not fail under normal circumstances.
-}
checkReturn :: (MonadIO m) => S2nTlsSys -> IO CInt -> m ()
checkReturn sys action = do
  result <- liftIO action
  case result of
    S2N_SUCCESS -> pure ()
    S2N_FAILURE -> throwS2nError sys
    S2N_CALLBACK_BLOCKED -> throwS2nError sys
    _ -> throwS2nError sys

{- | Check the return value of an s2n function, returning 'Left Blocked'
if the operation would block, or throwing an exception on other errors.
Use this for I/O operations like negotiate, send, recv, shutdown.
-}
checkReturnWithBlocked :: (MonadIO m) => S2nTlsSys -> Ptr S2nBlockedStatus -> IO CInt -> m (Either Blocked ())
checkReturnWithBlocked sys blockedPtr action = do
  result <- liftIO action
  blockedStatus <- liftIO $ peek blockedPtr
  case result of
    S2N_SUCCESS -> pure (Right ())
    S2N_FAILURE -> do
      case fromSysBlockedStatus blockedStatus of
        Just blocked -> pure (Left blocked)
        Nothing -> throwS2nError sys
    S2N_CALLBACK_BLOCKED -> do
      case fromSysBlockedStatus blockedStatus of
        Just blocked -> pure (Left blocked)
        Nothing -> throwS2nError sys
    _ -> throwS2nError sys
