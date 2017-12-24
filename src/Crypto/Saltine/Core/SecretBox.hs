-- |
-- Module      : Crypto.Saltine.Core.SecretBox
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Secret-key authenticated encryption:
-- "Crypto.Saltine.Core.SecretBox"
--
-- The 'secretbox' function encrypts and authenticates a message
-- 'ByteString' using a secret key and a nonce. The 'secretboxOpen'
-- function verifies and decrypts a ciphertext 'ByteString' using a
-- secret key and a nonce. If the ciphertext fails validation,
-- 'secretboxOpen' returns 'Nothing'.
--
-- The "Crypto.Saltine.Core.SecretBox" module is designed to meet
-- the standard notions of privacy and authenticity for a secret-key
-- authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Bellare and Namprempre, "Authenticated
-- encryption: relations among notions and analysis of the generic
-- composition paradigm," Lecture Notes in Computer Science 1976
-- (2000), 531–545, <http://www-cse.ucsd.edu/~mihir/papers/oem.html>.
--
-- Note that the length is not hidden. Unlike
-- "Crypto.Saltine.Unsafe.SecretBox", this module prevents nonce
-- reuse vulnerabilities by generating a new random nonce on every
-- call to 'secretbox'. The nonce is included in the ciphertext
-- (format: @nonce || ciphertext@) to remove the sudden death
-- properties of normal @xsalsa20poly1305@ while maintaining full
-- interoperability with unsafe versions of the scheme.
--
-- "Crypto.Saltine.Core.SecretBox" is
-- @crypto_secretbox_xsalsa20poly1305@, a particular combination of
-- Salsa20 and Poly1305 specified in \"Cryptography in NaCl\"
-- (<http://nacl.cr.yp.to/valid.html>). This function is conjectured
-- to meet the standard notions of privacy and authenticity.
--
-- This is version 2010.08.30 of the secretbox.html web page.
module Crypto.Saltine.Core.SecretBox (
  U.Key,
  secretbox, secretboxOpen,
  secretboxDetached, secretboxOpenDetached,
  U.newKey,
  ) where

import           Crypto.Saltine.Class
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Unsafe.SecretBox   as U

import qualified Data.ByteArray                    as B
import           Data.ByteString                     (ByteString)

-- | Encrypts a message. It is infeasible for an attacker to decrypt
-- the message as a random nonce is prepended to the message.
secretbox :: U.Key
          -> ByteString
          -- ^ Message
          -> IO ByteString
          -- ^ Ciphertext
secretbox key msg = do
  nonce <- U.newNonce
  let ciphertext = U.secretbox key nonce msg
  return $ B.append (encode nonce) ciphertext

-- | Encrypts a message. In contrast with 'secretbox', the result is not
-- serialized as one element and instead provided as an authentication tag and
-- ciphertext.
secretboxDetached :: U.Key
                  -> ByteString
                  -- ^ Message
                  -> IO (ByteString,ByteString)
                  -- ^ (Authentication Tag, Ciphertext)
secretboxDetached key msg = do
  nonce <- U.newNonce
  let (tag, ciphertext) = U.secretboxDetached key nonce msg
  return (tag, B.append (encode nonce) ciphertext)

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
secretboxOpen :: U.Key
              -> ByteString
              -- ^ Ciphertext
              -> Maybe ByteString
              -- ^ Message
secretboxOpen key cipher = do
  let (n, c) = split Bytes.secretBoxNonce cipher
  nonce <- decode n
  U.secretboxOpen key nonce c

-- | Decrypts a message. Returns 'Nothing' if the keys and message do
-- not match.
secretboxOpenDetached :: U.Key
                      -> ByteString
                      -- ^ Auth Tag
                      -> ByteString
                      -- ^ Ciphertext
                      -> Maybe ByteString
                      -- ^ Message
secretboxOpenDetached key tag cipher = do
  let (n, c) = split Bytes.secretBoxNonce cipher
  nonce <- decode n
  U.secretboxOpenDetached key nonce tag c
