-- |
-- Module      : Crypto.Saltine.Unsafe.KeyExchange
-- Copyright   :
-- License     : MIT
--
-- Maintainer  :
-- Stability   : experimental
-- Portability : non-portable
--
-- Key exchange abstraction:
-- "Crypto.Saltine.Unsafe.KeyExchange"
--
--
--
-- Note that the length is not hidden. Note also that it is the
-- caller's responsibility to ensure the uniqueness of nonces—for
-- example, by using nonce 1 for the first message, nonce 2 for the
-- second message, etc. Nonces are long enough that randomly generated
-- nonces have negligible risk of collision.
--

module Crypto.Saltine.Unsafe.KeyExchange (
  SecretKey, PublicKey, Keypair, Seed,
  SessionKeys,
  newKeypair, seedKeypair,
  clientSessionKeys, serverSessionKeys,
  kxAead, kxAeadOpen,
  kxSecretbox, kxSecretboxOpen,
  newAeadNonce, newSecretBoxNonce
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Core.AEAD          as AEAD
import           Crypto.Saltine.Core.SecretBox     as SecretBox
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import           Control.Applicative
import           Foreign.C
import           Foreign.Ptr
import           System.IO.Unsafe
import qualified Data.ByteString                   as S
import           Data.ByteString                      (ByteString)
import           Data.Maybe                           (fromJust)


-- | An opaque 'kx' cryptographic secret key.
newtype SecretKey = SK ByteString deriving (Eq, Ord)

instance IsEncoding SecretKey where
  decode v = if S.length v == Bytes.kxSK
           then Just (SK v)
           else Nothing
  {-# INLINE decode #-}
  encode (SK v) = v
  {-# INLINE encode #-}

-- | An opaque 'kx' cryptographic public key.
newtype PublicKey = PK ByteString deriving (Eq, Ord)

instance IsEncoding PublicKey where
  decode v = if S.length v == Bytes.kxPK
           then Just (PK v)
           else Nothing
  {-# INLINE decode #-}
  encode (PK v) = v
  {-# INLINE encode #-}

-- | A convenience type for keypairs
type Keypair = (SecretKey, PublicKey)

-- | An opaque pair of session keys for use with
-- 'clientAead', 'serverSecretBoxOpen' etc
data SessionKeys = SKs ByteString ByteString deriving (Eq, Ord)

instance IsEncoding SessionKeys where
  decode v = if S.length v == Bytes.kxSessionKey * 2
           then Just (SKs rx tx)
           else Nothing
    where rx = S.take Bytes.kxSessionKey v
          tx = S.drop Bytes.kxSessionKey v
  {-# INLINE decode #-}
  encode (SKs rx tx) = S.append rx tx
  {-# INLINE encode #-}

-- | An opaque key exchange seed
newtype Seed = Seed ByteString deriving (Eq, Ord)

instance IsEncoding Seed where
  decode v = if S.length v == Bytes.kxSeed
           then Just (Seed v)
           else Nothing
  {-# INLINE decode #-}
  encode (Seed v) = v
  {-# INLINE encode #-}

newKeypair :: IO Keypair
newKeypair = do
  ((_err, sk), pk) <- buildUnsafeByteString' Bytes.kxPK $ \pkbuf ->
    buildUnsafeByteString' Bytes.kxSK $ \skbuf ->
      c_kx_keypair pkbuf skbuf
  return (SK sk, PK pk)

seedKeypair :: Seed -> Keypair
seedKeypair (Seed s) = unsafePerformIO $ do
  ((_err, sk), pk) <- buildUnsafeByteString' Bytes.kxPK $ \pkbuf ->
    buildUnsafeByteString' Bytes.kxSK $ \skbuf ->
      constByteStrings [s] $ \[(ps, _)] ->
        c_kx_seed_keypair pkbuf skbuf ps
  return (SK sk, PK pk)

clientSessionKeys :: Keypair -> PublicKey -> Maybe SessionKeys
clientSessionKeys ((SK csk), (PK cpk)) (PK spk) =
  let ((err, rx), tx) = buildUnsafeByteString Bytes.kxSessionKey $ \rxbuf ->
        buildUnsafeByteString' Bytes.kxSessionKey $ \txbuf ->
          constByteStrings [cpk, csk, spk] $ \
            [(pcpk, _), (pcsk, _), (pspk, _)] ->
            c_kx_client_session_keys rxbuf txbuf pcpk pcsk pspk
  in hush . handleErrno err $ SKs rx tx

serverSessionKeys :: Keypair -> PublicKey -> Maybe SessionKeys
serverSessionKeys ((SK ssk), (PK spk)) (PK cpk) =
  let ((err, rx), tx) = buildUnsafeByteString Bytes.kxSessionKey $ \rxbuf ->
        buildUnsafeByteString' Bytes.kxSessionKey $ \txbuf ->
          constByteStrings [spk, ssk, cpk] $ \
            [(pspk, _), (pssk, _), (pcpk, _)] ->
            c_kx_server_session_keys rxbuf txbuf pspk pssk pcpk
  in hush . handleErrno err $ SKs rx tx

-- | Convert a session key to a 'secretbox' key
toSecretBoxKey :: ByteString -> SecretBox.Key
toSecretBoxKey k = fromJust $ decode k

-- | Convert a session key to an 'aead' key
toAEADKey :: ByteString -> AEAD.Key
toAEADKey k = fromJust $ decode k

-- | Convenience function for 'secretbox' nonce
newSecretBoxNonce :: IO SecretBox.Nonce
newSecretBoxNonce = SecretBox.newNonce

-- | Convenience function for 'aead' nonce
newAeadNonce :: IO AEAD.Nonce
newAeadNonce = AEAD.newNonce

-- | Like 'aead' but using the correct session key automatically
kxAead :: SessionKeys -> AEAD.Nonce -> ByteString -> ByteString -> ByteString
kxAead (SKs _ tx) = aead $ toAEADKey tx

-- | Like 'aeadOpen' but using the correct session key automatically
kxAeadOpen :: SessionKeys -> AEAD.Nonce -> ByteString -> ByteString -> Maybe ByteString
kxAeadOpen (SKs rx _) = aeadOpen $ toAEADKey rx

-- | Like 'secretbox' but using the correct session key automatically
kxSecretbox :: SessionKeys -> SecretBox.Nonce -> ByteString -> ByteString
kxSecretbox (SKs _ tx) = secretbox $ toSecretBoxKey tx

-- | Like 'secretboxOpen' but using the correct session key automatically
kxSecretboxOpen :: SessionKeys -> SecretBox.Nonce -> ByteString -> Maybe ByteString
kxSecretboxOpen (SKs rx _) = secretboxOpen $ toSecretBoxKey rx

foreign import ccall "crypto_kx_keypair"
  c_kx_keypair :: Ptr CChar
               -- | Public key output buffer
               -> Ptr CChar
               -- | Secret key output buffer
               -> IO CInt

foreign import ccall "crypto_kx_seed_keypair"
  c_kx_seed_keypair :: Ptr CChar
                    -- | Public key output buffer
                    -> Ptr CChar
                    -- | Secret key output buffer
                    -> Ptr CChar
                    -- | Constant seed buffer
                    -> IO CInt

foreign import ccall "crypto_kx_client_session_keys"
  c_kx_client_session_keys :: Ptr CChar
                           -- | Client's receiving key output buffer
                           -> Ptr CChar
                           -- | Client's sending key output buffer
                           -> Ptr CChar
                           -- | Constant client public key buffer
                           -> Ptr CChar
                           -- | Constant client secret key buffer
                           -> Ptr CChar
                           -- | Constant server public key buffer
                           -> IO CInt
                           -- | 0 for success, -1 for
                           -- unacceptable server public key

foreign import ccall "crypto_kx_server_session_keys"
  c_kx_server_session_keys :: Ptr CChar
                           -- | Server's sending key output buffer
                           -> Ptr CChar
                           -- | Server's receiving key output buffer
                           -> Ptr CChar
                           -- | Constant server public key buffer
                           -> Ptr CChar
                           -- | Constant server secret key buffer
                           -> Ptr CChar
                           -- | Constant client public key buffer
                           -> IO CInt
                           -- | 0 for success, -1 for
                           -- unacceptable client public key
