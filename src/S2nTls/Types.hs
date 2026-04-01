-- |
-- Module      : S2nTls.Types
-- Copyright   : (c) 2025
-- License     : BSD-3-Clause
-- Maintainer  : your.email@example.com
-- Stability   : experimental
-- Portability : non-portable (requires s2n-tls C library)
--
-- This module provides memory-safe wrappers around s2n-tls opaque types
-- using 'ForeignPtr' for automatic resource management.
--
{-# LANGUAGE PatternSynonyms #-}
module S2nTls.Types
    ( -- * Safe Pointer Types
      Config
    , Connection (..)
    , CertChainAndKey

      -- * Re-exported Enumerations
    , Mode (..)
    , pattern Server
    , pattern Client
    , Blocked (..)
    , CertAuthType (..)
    , pattern CertAuthNone
    , pattern CertAuthRequired
    , pattern CertAuthOptional

      -- * TLS Versions
    , TlsVersion (..)
    , pattern SSLv2
    , pattern SSLv3
    , pattern TLS10
    , pattern TLS11
    , pattern TLS12
    , pattern TLS13
    ) where

import Data.IORef (IORef)
import Foreign.C.Types (CInt)
import Foreign.ForeignPtr (ForeignPtr)
import S2nTls.Error (Blocked (..))
import S2nTls.Sys.Types
    ( S2nCertChainAndKey
    , S2nConfig
    , S2nConnection
    , S2nMode
    , pattern S2N_CLIENT
    , pattern S2N_SERVER
    , S2nCertAuthType
    , pattern S2N_CERT_AUTH_NONE
    , pattern S2N_CERT_AUTH_OPTIONAL
    , pattern S2N_CERT_AUTH_REQUIRED
    )

-- | A managed TLS configuration.
-- Resources are automatically freed when the 'Config' is garbage collected.
type Config = ForeignPtr S2nConfig

-- | A managed TLS connection.
-- Resources are automatically freed when the 'Connection' is garbage collected.
-- The connection also tracks file descriptors for blocking I/O support.
data Connection = Connection
    { connPtr :: !(ForeignPtr S2nConnection)
    -- ^ The underlying s2n connection pointer
    , connReadFd :: !(IORef (Maybe CInt))
    -- ^ Read file descriptor (set via 'setReadFd' or 'setFd')
    , connWriteFd :: !(IORef (Maybe CInt))
    -- ^ Write file descriptor (set via 'setWriteFd' or 'setFd')
    }

-- | A managed certificate chain and key pair.
-- Resources are automatically freed when garbage collected.
type CertChainAndKey = ForeignPtr S2nCertChainAndKey

-- | Connection mode (client or server).
newtype Mode = Mode {unMode :: S2nMode}
    deriving (Eq, Show)

pattern Server :: Mode
pattern Server = Mode S2N_SERVER

pattern Client :: Mode
pattern Client = Mode S2N_CLIENT

{-# COMPLETE Server, Client #-}

-- | Client certificate authentication type.
newtype CertAuthType = CertAuthType {unCertAuthType :: S2nCertAuthType}
    deriving (Eq, Show)

pattern CertAuthNone :: CertAuthType
pattern CertAuthNone = CertAuthType S2N_CERT_AUTH_NONE

pattern CertAuthRequired :: CertAuthType
pattern CertAuthRequired = CertAuthType S2N_CERT_AUTH_REQUIRED

pattern CertAuthOptional :: CertAuthType
pattern CertAuthOptional = CertAuthType S2N_CERT_AUTH_OPTIONAL

{-# COMPLETE CertAuthNone, CertAuthRequired, CertAuthOptional #-}

-- | TLS protocol version.
newtype TlsVersion = TlsVersion {unTlsVersion :: CInt}
    deriving (Eq, Ord, Show)

pattern SSLv2 :: TlsVersion
pattern SSLv2 = TlsVersion 20

pattern SSLv3 :: TlsVersion
pattern SSLv3 = TlsVersion 30

pattern TLS10 :: TlsVersion
pattern TLS10 = TlsVersion 31

pattern TLS11 :: TlsVersion
pattern TLS11 = TlsVersion 32

pattern TLS12 :: TlsVersion
pattern TLS12 = TlsVersion 33

pattern TLS13 :: TlsVersion
pattern TLS13 = TlsVersion 34

{-# COMPLETE SSLv2, SSLv3, TLS10, TLS11, TLS12, TLS13 #-}
