-- |
-- Module      : Crypto.Saltine.Core.AEAD
-- Copyright   : (c) Thomas DuBuisson 2017
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Secret-key authenticated encryption with additional data (AEAD):
-- "Crypto.Saltine.Core.AEAD"
--
-- The 'aead' function encrypts and authenticates a message
-- 'ByteString' and additional authenticated data 'ByteString'
-- using a secret key and a nonce. The 'aeadOpen'
-- function verifies and decrypts a ciphertext 'ByteString' using a
-- secret key and a nonce. If the ciphertext fails validation,
-- 'aeadOpen' returns 'Nothing'.
--
-- The "Crypto.Saltine.Core.AEAD" module is designed to meet
-- the standard notions of privacy and authenticity for a secret-key
-- authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Bellare and Namprempre, "Authenticated
-- encryption: relations among notions and analysis of the generic
-- composition paradigm," Lecture Notes in Computer Science 1976
-- (2000), 531–545, <http://www-cse.ucsd.edu/~mihir/papers/oem.html>.
--
-- Note that the length is not hidden. Note also that it is the
-- caller's responsibility to ensure the uniqueness of nonces—for
-- example, by using nonce 1 for the first message, nonce 2 for the
-- second message, etc. Nonces are long enough that randomly generated
-- nonces have negligible risk of collision.

module Crypto.Saltine.Core.AEAD (
  Key, Nonce,
  aead, aeadOpen,
  aeadDetached, aeadOpenDetached,
  newKey, newNonce
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import           Control.Applicative
import           Foreign.C
import           Foreign.Ptr
import qualified Data.ByteArray                    as B
import           Data.ByteArray                      (ByteArrayAccess, ByteArray, Bytes, ScrubbedBytes)
import qualified Data.ByteString                   as S
import           Data.ByteString                     (ByteString)

-- $types

-- | An opaque 'secretbox' cryptographic key.
newtype Key = Key ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding Key where
  decode v = if B.length v == Bytes.secretBoxKey
           then Just (Key $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = B.convert v
  {-# INLINE encode #-}

-- | An opaque 'secretbox' nonce.
newtype Nonce = Nonce Bytes deriving (Eq, Ord)

instance IsEncoding Nonce where
  decode v = if B.length v == Bytes.secretBoxNonce
           then Just (Nonce $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = B.convert v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero            = Nonce (B.replicate Bytes.secretBoxNonce 0)
  nudge (Nonce n) = Nonce (nudgeBA n)

-- | Creates a random key of the correct size for 'secretbox'.
newKey :: IO Key
newKey = Key <$> randomByteArray Bytes.secretBoxKey

-- | Creates a random nonce of the correct size for 'secretbox'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomByteArray Bytes.secretBoxNonce


-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message so long as the 'Nonce' is never repeated.
aead :: Key -> Nonce
          -> ByteString
          -- ^ Message
          -> ByteString
          -- ^ AAD
          -> ByteString
          -- ^ Ciphertext
aead (Key key) (Nonce nonce) msg aad =
  snd . buildUnsafeByteArray clen $ \pc ->
    constByteArray4 key msg aad nonce $ \pk pm pa pn ->
      c_aead pc nullPtr pm (fromIntegral mlen) pa (fromIntegral alen) nullPtr pn pk
  where mlen    = S.length msg
        alen    = S.length aad
        clen    = mlen + Bytes.aead_xchacha20poly1305_ietf_ABYTES

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
aeadOpen :: Key -> Nonce
         -> ByteString
         -- ^ Ciphertext
         -> ByteString
         -- ^ AAD
         -> Maybe ByteString
         -- ^ Message
aeadOpen (Key key) (Nonce nonce) cipher aad =
  let (err, vec) = buildUnsafeByteArray mlen $ \pm ->
        constByteArray4 key cipher aad nonce $ \pk pc pa pn ->
          c_aead_open pm nullPtr nullPtr pc (fromIntegral clen) pa (fromIntegral alen) pn pk
  in hush . handleErrno err $ vec
  where clen   = S.length cipher
        alen   = S.length aad
        mlen   = clen - Bytes.aead_xchacha20poly1305_ietf_ABYTES

-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message so long as the 'Nonce' is never repeated.
aeadDetached :: Key -> Nonce
          -> ByteString
          -- ^ Message
          -> ByteString
          -- ^ AAD
          -> (ByteString,ByteString)
          -- ^ Tag, Ciphertext
aeadDetached (Key key) (Nonce nonce) msg aad =
  buildUnsafeByteArray clen $ \pc ->
   fmap snd . buildUnsafeByteArray' tlen $ \pt ->
    constByteArray4 key msg aad nonce $ \pk pm pa pn ->
      c_aead_detached pc pt nullPtr pm (fromIntegral mlen) pa (fromIntegral alen) nullPtr pn pk
  where mlen    = S.length msg
        alen    = S.length aad
        clen    = mlen
        tlen    = Bytes.aead_xchacha20poly1305_ietf_ABYTES

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
aeadOpenDetached :: Key -> Nonce
         -> ByteString
         -- ^ Tag
         -> ByteString
         -- ^ Ciphertext
         -> ByteString
         -- ^ AAD
         -> Maybe ByteString
         -- ^ Message
aeadOpenDetached (Key key) (Nonce nonce) tag cipher aad
    | S.length tag /= tlen = Nothing
    | otherwise =
  let (err, vec) = buildUnsafeByteArray len $ \pm ->
        constByteArray5 key tag cipher aad nonce $ \pk pt pc pa pn ->
          c_aead_open_detached pm nullPtr pc (fromIntegral len) pt pa (fromIntegral alen) pn pk
  in hush . handleErrno err $ vec
  where len    = S.length cipher
        alen   = S.length aad
        tlen   = Bytes.aead_xchacha20poly1305_ietf_ABYTES

-- | The aead C API uses C strings. Always returns 0.
foreign import ccall "crypto_aead_xchacha20poly1305_ietf_encrypt"
  c_aead :: Ptr CChar
              -- ^ Cipher output buffer
              -> Ptr CULLong
              -- ^ Cipher output bytes used
              -> Ptr CChar
              -- ^ Constant message input buffer
              -> CULLong
              -- ^ Length of message input buffer
              -> Ptr CChar
              -- ^ Constant aad input buffer
              -> CULLong
              -- ^ Length of aad input buffer
              -> Ptr CChar
              -- ^ Unused 'nsec' value (must be NULL)
              -> Ptr CChar
              -- ^ Constant nonce buffer
              -> Ptr CChar
              -- ^ Constant key buffer
              -> IO CInt

-- | The aead open C API uses C strings. Returns 0 if successful.
foreign import ccall "crypto_aead_xchacha20poly1305_ietf_decrypt"
  c_aead_open :: Ptr CChar
              -- ^ Message output buffer
              -> Ptr CULLong
              -- ^ Message output bytes used
              -> Ptr CChar
              -- ^ Unused 'nsec' value (must be NULL)
              -> Ptr CChar
              -- ^ Constant ciphertext input buffer
              -> CULLong
              -- ^ Length of ciphertext input buffer
              -> Ptr CChar
              -- ^ Constant aad input buffer
              -> CULLong
              -- ^ Length of aad input buffer
              -> Ptr CChar
              -- ^ Constant nonce buffer
              -> Ptr CChar
              -- ^ Constant key buffer
              -> IO CInt

-- | The aead C API uses C strings. Always returns 0.
foreign import ccall "crypto_aead_xchacha20poly1305_ietf_encrypt_detached"
  c_aead_detached :: Ptr CChar
              -- ^ Cipher output buffer
              -> Ptr CChar
              -- ^ Tag output buffer
              -> Ptr CULLong
              -- ^ Tag bytes used
              -> Ptr CChar
              -- ^ Constant message input buffer
              -> CULLong
              -- ^ Length of message input buffer
              -> Ptr CChar
              -- ^ Constant aad input buffer
              -> CULLong
              -- ^ Length of aad input buffer
              -> Ptr CChar
              -- ^ Unused 'nsec' value (must be NULL)
              -> Ptr CChar
              -- ^ Constant nonce buffer
              -> Ptr CChar
              -- ^ Constant key buffer
              -> IO CInt

-- | The aead open C API uses C strings. Returns 0 if successful.
foreign import ccall "crypto_aead_xchacha20poly1305_ietf_decrypt_detached"
  c_aead_open_detached :: Ptr CChar
              -- ^ Message output buffer
              -> Ptr CChar
              -- ^ Unused 'nsec' value (must be NULL)
              -> Ptr CChar
              -- ^ Constant ciphertext input buffer
              -> CULLong
              -- ^ Length of ciphertext input buffer
              -> Ptr CChar
              -- ^ Constant tag input buffer
              -> Ptr CChar
              -- ^ Constant aad input buffer
              -> CULLong
              -- ^ Length of aad input buffer
              -> Ptr CChar
              -- ^ Constant nonce buffer
              -> Ptr CChar
              -- ^ Constant key buffer
              -> IO CInt
