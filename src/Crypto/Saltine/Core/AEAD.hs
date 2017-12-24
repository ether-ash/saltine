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
  U.Key, U.Nonce,
  U.aead, U.aeadOpen,
  U.aeadDetached, U.aeadOpenDetached,
  U.newKey, U.newNonce
  ) where

import qualified Crypto.Saltine.Unsafe.AEAD as U
