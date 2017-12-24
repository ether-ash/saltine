-- |
-- Module      : Crypto.Saltine.Unsafe.Stream
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Secret-key encryption:
-- "Crypto.Saltine.Unsafe.Stream"
--
-- The 'stream' function produces a sized stream 'ByteString' as a
-- function of a secret key and a nonce. The 'xor' function encrypts a
-- message 'ByteString' using a secret key and a nonce.  The 'xor'
-- function guarantees that the ciphertext has the same length as the
-- plaintext, and is the @plaintext `xor` stream k n@. Consequently
-- 'xor' can also be used to decrypt.
--
-- The 'stream' function, viewed as a function of the nonce for a
-- uniform random key, is designed to meet the standard notion of
-- unpredictability (\"PRF\"). For a formal definition see, e.g.,
-- Section 2.3 of Bellare, Kilian, and Rogaway, \"The security of the
-- cipher block chaining message authentication code,\" Journal of
-- Computer and System Sciences 61 (2000), 362–399;
-- <http://www-cse.ucsd.edu/~mihir/papers/cbc.html>. This means that
-- an attacker cannot distinguish this function from a uniform random
-- function. Consequently, if a series of messages is encrypted by
-- 'xor' with /a different nonce for each message/, the ciphertexts
-- are indistinguishable from uniform random strings of the same
-- length.
--
-- Note that the length is not hidden. Note also that it is the
-- caller's responsibility to ensure the uniqueness of nonces—for
-- example, by using nonce 1 for the first message, nonce 2 for the
-- second message, etc. Nonces are long enough that randomly generated
-- nonces have negligible risk of collision.
--
-- Saltine does not make any promises regarding the resistance of
-- crypto_stream to \"related-key attacks.\" It is the caller's
-- responsibility to use proper key-derivation functions.
--
-- "Crypto.Saltine.Unsafe.Stream" is @crypto_stream_xsalsa20@, a
-- particular cipher specified in \"Cryptography in NaCl\"
-- (<http://nacl.cr.yp.to/valid.html>), Section 7. This cipher is
-- conjectured to meet the standard notion of unpredictability.
--
-- This is version 2010.08.30 of the stream.html web page.

module Crypto.Saltine.Unsafe.Stream (
  Key, Nonce,
  newKey, newNonce,
  stream, xor
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

-- | An opaque 'stream' cryptographic key.
newtype Key = Key ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding Key where
  decode v = if B.length v == Bytes.streamKey
           then Just (Key $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (Key v) = B.convert v
  {-# INLINE encode #-}

-- | An opaque 'stream' nonce.
newtype Nonce = Nonce ByteString deriving (Eq, Ord)

instance IsNonce Nonce where
  zero = Nonce (B.replicate Bytes.streamNonce 0)
  nudge (Nonce n) = Nonce (nudgeBA n)

instance IsEncoding Nonce where
  decode v = if B.length v == Bytes.streamNonce
           then Just (Nonce $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = B.convert v
  {-# INLINE encode #-}

-- | Creates a random key of the correct size for 'stream' and 'xor'.
newKey :: IO Key
newKey = Key <$> randomByteArray Bytes.streamKey

-- | Creates a random nonce of the correct size for 'stream' and
-- 'xor'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomByteArray Bytes.streamNonce

-- | Generates a cryptographic random stream indexed by the 'Key' and
-- 'Nonce'. These streams are indistinguishable from random noise so
-- long as the 'Nonce' is not used more than once.
stream :: Key -> Nonce -> Int
       -> ByteString
       -- ^ Cryptographic stream
stream (Key key) (Nonce nonce) n =
  snd . buildUnsafeByteArray n $ \ps ->
    constByteArray2 key nonce $ \pk pn ->
      c_stream ps (fromIntegral n) pn pk

-- | Computes the exclusive-or between a message and a cryptographic
-- random stream indexed by the 'Key' and the 'Nonce'. This renders
-- the output indistinguishable from random noise so long as the
-- 'Nonce' is not used more than once. /Note:/ while this can be used
-- for encryption and decryption, it is /possible for an attacker to/
-- /manipulate the message in transit without detection/. USE AT YOUR
-- OWN RISK.
xor :: Key -> Nonce
    -> ByteString
    -- ^ Message
    -> ByteString
    -- ^ Ciphertext
xor (Key key) (Nonce nonce) msg =
  snd . buildUnsafeByteArray len $ \pc ->
    constByteArray3 key nonce msg $ \pk pn pm ->
      c_stream_xor pc pm (fromIntegral len) pn pk
  where len = S.length msg

foreign import ccall "crypto_stream"
  c_stream :: Ptr CChar
           -- ^ Stream output buffer
           -> CULLong
           -- ^ Length of stream to generate
           -> Ptr CChar
           -- ^ Constant nonce buffer
           -> Ptr CChar
           -- ^ Constant key buffer
           -> IO CInt
           -- ^ Always 0

foreign import ccall "crypto_stream_xor"
  c_stream_xor :: Ptr CChar
               -- ^ Ciphertext output buffer
               -> Ptr CChar
               -- ^ Constant message buffer
               -> CULLong
               -- ^ Length of message buffer
               -> Ptr CChar
               -- ^ Constant nonce buffer
               -> Ptr CChar
               -- ^ Constant key buffer
               -> IO CInt
               -- ^ Always 0
