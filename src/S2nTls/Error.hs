{-# LANGUAGE PatternSynonyms #-}

-- \|
-- Module      : S2nTls.Error
-- Description : Error types and exception handling for s2n-tls
-- License     : BSD-3-Clause
--
-- This module provides Haskell-idiomatic error handling for s2n-tls operations.
-- Truly exceptional errors (internal errors, usage errors, protocol violations)
-- are thrown as exceptions. Expected "errors" like blocking on I/O are returned
-- via 'Either'.

{- |
Module      : S2nTls.Error
Copyright   : (c) 2026
License     : BSD-3-Clause
Maintainer  : daniel.goertzen@gmail.com
-}
module S2nTls.Error (
  -- * Exceptions
  S2nError (..),
  S2nErrorType (..),

  -- * Blocking Status
  Blocked (..),

  -- * Internal Utilities
  fromSysError,
  fromSysEither,
  checkReturnWithBlocked,
) where

import Foreign.C.Types (CInt (..))
import S2nTls.Sys.Types (
  S2nBlockedStatus (..),
  S2nTlsSys (..),
  pattern S2N_BLOCKED_ON_APPLICATION_INPUT,
  pattern S2N_BLOCKED_ON_EARLY_DATA,
  pattern S2N_BLOCKED_ON_READ,
  pattern S2N_BLOCKED_ON_WRITE,
  pattern S2N_ERR_T_ALERT,
  pattern S2N_ERR_T_BLOCKED,
  pattern S2N_ERR_T_CLOSED,
  pattern S2N_ERR_T_INTERNAL,
  pattern S2N_ERR_T_IO,
  pattern S2N_ERR_T_OK,
  pattern S2N_ERR_T_PROTO,
  pattern S2N_ERR_T_USAGE,
  pattern S2N_NOT_BLOCKED,
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
  , s2nErrorDebug :: !String
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

-- | Convert a sys-level S2nError to our richer S2nError type.
fromSysError :: (MonadIO m) => S2nTlsSys -> Sys.S2nError -> m S2nError
fromSysError sys sysErr = do
  let errCode = Sys.s2nErrorCode sysErr
  errTypeRaw <- liftIO $ s2n_error_get_type sys errCode
  let errType = fromSysErrorType errTypeRaw
  msgPtr <- liftIO $ s2n_strerror sys errCode nullPtr
  msg <-
    if msgPtr == nullPtr
      then pure "Unknown error"
      else peekCString msgPtr
  pure
    S2nError
      { s2nErrorType = errType
      , s2nErrorCode = errCode
      , s2nErrorMessage = msg
      , s2nErrorDebug = Sys.s2nErrorDebugMessage sysErr
      }

{- | Handle an Either result from the sys library, converting errors and
throwing them as exceptions.
-}
fromSysEither :: (MonadIO m) => S2nTlsSys -> Either Sys.S2nError a -> m a
fromSysEither sys (Left sysErr) = do
  err <- fromSysError sys sysErr
  throwIO err
fromSysEither _ (Right a) = pure a

{- | Check the return value of an s2n function, returning 'Left Blocked'
if the operation would block, or throwing an exception on other errors.
Use this for I/O operations like negotiate, send, recv, shutdown.
-}
checkReturnWithBlocked :: (MonadIO m) => S2nTlsSys -> Ptr S2nBlockedStatus -> IO (Either Sys.S2nError CInt) -> m (Either Blocked ())
checkReturnWithBlocked sys blockedPtr action = do
  result <- liftIO action
  blockedStatus <- liftIO $ peek blockedPtr
  case result of
    Right _ -> pure (Right ())
    Left _sysErr -> do
      case fromSysBlockedStatus blockedStatus of
        Just blocked -> pure (Left blocked)
        Nothing -> do
          err <- fromSysError sys _sysErr
          throwIO err
