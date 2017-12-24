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
  U.Key,
  aead, aeadOpen,
  aeadDetached, aeadOpenDetached,
  U.newKey
  ) where

import           Crypto.Saltine.Class
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Unsafe.AEAD        as U

import qualified Data.ByteArray                    as B
import           Data.ByteString                     (ByteString)

-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message as a random nonce is prepended to the ciphertext.
aead :: U.Key
     -> ByteString
     -- ^ Message
     -> ByteString
     -- ^ AAD
     -> IO ByteString
     -- ^ Ciphertext
aead key msg aad = do
  nonce <- U.newNonce
  let ciphertext = U.aead key nonce msg aad
  return $ B.append (encode nonce) ciphertext

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
aeadOpen :: U.Key
         -> ByteString
         -- ^ Ciphertext
         -> ByteString
         -- ^ AAD
         -> Maybe ByteString
         -- ^ Message
aeadOpen key cipher aad = do
  let (n, c) = split Bytes.secretBoxNonce cipher
  nonce <- decode n
  U.aeadOpen key nonce c aad

-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message as a random nonce is prepended to the ciphertext.
aeadDetached :: U.Key
             -> ByteString
             -- ^ Message
             -> ByteString
             -- ^ AAD
             -> IO (ByteString, ByteString)
             -- ^ Tag, ciphertext
aeadDetached key msg aad = do
  nonce <- U.newNonce
  let (tag, ciphertext) = U.aeadDetached key nonce msg aad
  return (tag, B.append (encode nonce) ciphertext)

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
aeadOpenDetached :: U.Key
                 -> ByteString
                 -- ^ Tag
                 -> ByteString
                 -- ^ Ciphertext
                 -> ByteString
                 -- ^ AAD
                 -> Maybe ByteString
                 -- ^ Message
aeadOpenDetached key tag cipher aad = do
  let (n, c) = split Bytes.secretBoxNonce cipher
  nonce <- decode n
  U.aeadOpenDetached key nonce tag c aad
