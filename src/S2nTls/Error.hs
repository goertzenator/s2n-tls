{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : S2nTls.Error
Copyright   : (c) 2026
License     : BSD-3-Clause
Maintainer  : daniel.goertzen@gmail.com

Error handling utilities for s2n-tls operations. The core error types
('S2nError', 'S2nErrorType', 'S2nBlockedStatus') are defined in
'S2nTls.Ffi.Types' and re-exported here for convenience. This module
also provides functions to query error classification and human-readable
messages.
-}
module S2nTls.Error (
  -- * Error Types (re-exported from S2nTls.Ffi.Types)
  S2nError (..),
  S2nErrorType (..),
  pattern S2nErrTOk,
  pattern S2nErrTIo,
  pattern S2nErrTClosed,
  pattern S2nErrTBlocked,
  pattern S2nErrTAlert,
  pattern S2nErrTProto,
  pattern S2nErrTInternal,
  pattern S2nErrTUsage,

  -- * Blocking Status (re-exported)
  S2nBlockedStatus (..),
  pattern S2nNotBlocked,
  pattern S2nBlockedOnRead,
  pattern S2nBlockedOnWrite,
  pattern S2nBlockedOnApplicationInput,
  pattern S2nBlockedOnEarlyData,

  -- * Error Query Functions
  getErrorType,
  getErrorMessage,

  -- * Internal Utilities
  fromFfiEither,
  checkReturnWithBlocked,
) where

import Control.Exception (throwIO)
import Foreign (Ptr, nullPtr, peek)
import Foreign.C.String (peekCString)
import S2nTls.Ffi.Types (
  S2nBlockedStatus (..),
  S2nError (..),
  S2nErrorType (..),
  S2nTlsFfi (..),
  pattern S2nBlockedOnApplicationInput,
  pattern S2nBlockedOnEarlyData,
  pattern S2nBlockedOnRead,
  pattern S2nBlockedOnWrite,
  pattern S2nErrTAlert,
  pattern S2nErrTBlocked,
  pattern S2nErrTClosed,
  pattern S2nErrTInternal,
  pattern S2nErrTIo,
  pattern S2nErrTOk,
  pattern S2nErrTProto,
  pattern S2nErrTUsage,
  pattern S2nNotBlocked,
 )

-- | Query the error type classification for an 'S2nError' via @s2n_error_get_type@.
getErrorType :: S2nTlsFfi -> S2nError -> IO S2nErrorType
getErrorType ffi err = s2n_error_get_type ffi (s2nErrorCode err)

-- | Query the human-readable message for an 'S2nError' via @s2n_strerror@.
getErrorMessage :: S2nTlsFfi -> S2nError -> IO String
getErrorMessage ffi err = do
  msgPtr <- s2n_strerror ffi (s2nErrorCode err) nullPtr
  if msgPtr == nullPtr
    then pure "Unknown error"
    else peekCString msgPtr

-- | Throw the 'S2nError' from an 'Either' result as an exception, returning the success value.
fromFfiEither :: Either S2nError a -> IO a
fromFfiEither (Left err) = throwIO err
fromFfiEither (Right a) = pure a

{- | Check the return value of an s2n function that reports a blocked status.
Returns @'Left' blockedStatus@ (never 'S2nNotBlocked') if the call would block,
@'Right' value@ on success, or throws the error as an exception otherwise.
-}
checkReturnWithBlocked
  :: S2nTlsFfi
  -> Ptr S2nBlockedStatus
  -> Either S2nError a
  -> IO (Either S2nBlockedStatus a)
checkReturnWithBlocked ffi blockedPtr result = case result of
  Right a -> pure (Right a)
  Left err -> do
    errType <- getErrorType ffi err
    case errType of
      S2nErrTBlocked -> do
        blockedStatus <- peek blockedPtr
        case blockedStatus of
          S2nNotBlocked -> throwIO err
          _ -> pure (Left blockedStatus)
      _ -> throwIO err
