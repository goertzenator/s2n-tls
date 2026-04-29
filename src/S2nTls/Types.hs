{-# LANGUAGE PatternSynonyms #-}

{- |
Module      : S2nTls.Types
Copyright   : (c) 2026
License     : BSD-3-Clause
Maintainer  : daniel.goertzen@gmail.com

This module provides memory-safe wrappers around s2n-tls opaque types
using 'Foreign.ForeignPtr.ForeignPtr' for automatic resource management.
-}
module S2nTls.Types (
  -- * Safe Pointer Types
  Config (..),
  Connection (..),
  CertChainAndKey,

  -- * Re-exported Enumerations
  Mode (..),
  pattern Server,
  pattern Client,
  CertAuthType (..),
  pattern CertAuthNone,
  pattern CertAuthRequired,
  pattern CertAuthOptional,

  -- * TLS Versions
  TlsVersion (..),
  pattern SSLv2,
  pattern SSLv3,
  pattern TLS10,
  pattern TLS11,
  pattern TLS12,
  pattern TLS13,
) where

import Data.IORef (IORef)
import Foreign.C.Types (CInt)
import Foreign.ForeignPtr (ForeignPtr)
import Network.Socket qualified as Net
import S2nTls.Ffi.Types (
  S2nCertAuthType,
  S2nCertChainAndKey,
  S2nConfig,
  S2nConnection,
  S2nMode,
  S2nSessionTicketFn,
  pattern S2nCertAuthNone,
  pattern S2nCertAuthOptional,
  pattern S2nCertAuthRequired,
  pattern S2nClient,
  pattern S2nServer,
 )

{- | A managed TLS configuration.
Resources are automatically freed when the 'Config' is garbage collected.
The Config also holds references to any CertChainAndKey objects added to it
to prevent them from being garbage collected.
-}
data Config = Config
  { configPtr :: !(ForeignPtr S2nConfig)
  -- ^ The underlying s2n config pointer
  , configCertKeys :: !(IORef [CertChainAndKey])
  -- ^ Certificate chain and key pairs added to this config
  , configSessionTicketCb :: !(IORef (Maybe S2nSessionTicketFn))
  -- ^ Session ticket callback FunPtr (kept alive to prevent GC)
  }

instance Show Config where
  show _ = "Config {<opaque>}"

{- | A managed TLS connection.
Resources are automatically freed when the 'Connection' is garbage collected.
The connection also tracks file descriptors for blocking I/O support,
and holds references to Config and CertChainAndKey to prevent GC.
-}
data Connection = Connection
  { connPtr :: !(ForeignPtr S2nConnection)
  -- ^ The underlying s2n connection pointer
  , connReadFd :: !(IORef (Maybe CInt))
  -- ^ Read file descriptor (set via 'S2nTls.Connection.setReadFd' or 'S2nTls.Connection.setFd')
  , connWriteFd :: !(IORef (Maybe CInt))
  -- ^ Write file descriptor (set via 'S2nTls.Connection.setWriteFd' or 'S2nTls.Connection.setFd')
  , connConfig :: !(IORef (Maybe (ForeignPtr S2nConfig)))
  -- ^ The currently assigned config (kept alive to prevent GC)
  -- , connCertKeys :: !(IORef [ForeignPtr S2nCertChainAndKey])
  -- ^ Certificate chain and key pairs (kept alive to prevent GC)
  , connSocket :: !(IORef (Maybe Net.Socket))
  -- ^ Socket reference (kept alive to prevent GC)
  }

instance Show Connection where
  show _ = "Connection {<opaque>}"

{- | A managed certificate chain and key pair.
Resources are automatically freed when garbage collected.
-}
type CertChainAndKey = ForeignPtr S2nCertChainAndKey

-- | Connection mode (client or server).
newtype Mode = Mode {unMode :: S2nMode}
  deriving (Eq, Show)

-- | Server-side connection mode.
pattern Server :: Mode
pattern Server = Mode S2nServer

-- | Client-side connection mode.
pattern Client :: Mode
pattern Client = Mode S2nClient

{-# COMPLETE Server, Client #-}

-- | Client certificate authentication type.
newtype CertAuthType = CertAuthType {unCertAuthType :: S2nCertAuthType}
  deriving (Eq, Show)

-- | Do not request a client certificate.
pattern CertAuthNone :: CertAuthType
pattern CertAuthNone = CertAuthType S2nCertAuthNone

-- | Require a client certificate; reject connections that do not provide one.
pattern CertAuthRequired :: CertAuthType
pattern CertAuthRequired = CertAuthType S2nCertAuthRequired

-- | Request a client certificate but accept connections that do not provide one.
pattern CertAuthOptional :: CertAuthType
pattern CertAuthOptional = CertAuthType S2nCertAuthOptional

{-# COMPLETE CertAuthNone, CertAuthRequired, CertAuthOptional #-}

-- | TLS protocol version.
newtype TlsVersion = TlsVersion {unTlsVersion :: CInt}
  deriving (Eq, Ord, Show)

-- | SSL 2.0 (deprecated, insecure).
pattern SSLv2 :: TlsVersion
pattern SSLv2 = TlsVersion 20

-- | SSL 3.0 (deprecated, insecure).
pattern SSLv3 :: TlsVersion
pattern SSLv3 = TlsVersion 30

-- | TLS 1.0 (deprecated).
pattern TLS10 :: TlsVersion
pattern TLS10 = TlsVersion 31

-- | TLS 1.1 (deprecated).
pattern TLS11 :: TlsVersion
pattern TLS11 = TlsVersion 32

-- | TLS 1.2.
pattern TLS12 :: TlsVersion
pattern TLS12 = TlsVersion 33

-- | TLS 1.3.
pattern TLS13 :: TlsVersion
pattern TLS13 = TlsVersion 34

{-# COMPLETE SSLv2, SSLv3, TLS10, TLS11, TLS12, TLS13 #-}
