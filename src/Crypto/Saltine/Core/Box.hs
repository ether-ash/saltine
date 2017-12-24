-- |
-- Module      : Crypto.Saltine.Core.Box
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Public-key cryptography abstraction:
-- "Crypto.Saltine.Core.Box"
--
-- This module consists of functions dealing with two public-key
-- cryptography concepts in libsodium.
--
-- The first one is an authenticated encryption scheme. In this
-- scheme, the 'box' function encrypts and authenticates a message
-- 'ByteString' using the sender's secret key, the receiver's public
-- key, and a nonce. The 'boxOpen' function verifies and decrypts a
-- ciphertext 'ByteString' using the receiver's secret key, the
-- sender's public key, and a nonce. If the ciphertext fails
-- verification, 'boxOpen' returns 'Nothing'.
--
-- The set of box functions is designed to meet the
-- standard notions of privacy and third-party unforgeability for a
-- public-key authenticated-encryption scheme using nonces. For formal
-- definitions see, e.g., Jee Hea An, "Authenticated encryption in the
-- public-key setting: security notions and analyses,"
-- <http://eprint.iacr.org/2001/079>.
--
-- Unlike "Crypto.Saltine.Unsafe.Box", this module prevents nonce
-- reuse vulnerabilities by generating a new random nonce for every
-- call to 'box'. The nonce is included in the ciphertext
-- (format: @nonce || ciphertext@) to remove the sudden death
-- properties of normal @xsalsa20poly1305@ while maintaining full
-- interoperability with unsafe versions of the scheme.
--
-- The second concept is sealed boxes, which provide encryption and
-- preservation of integrity, but not authentication. Technically,
-- the sender of a message generates a keypair, uses the regular
-- box mechanism, attaches the public key to the message and then
-- immediately destroys the private key. This is useful, e.g. when
-- the receiver cannot know the sender's public key in advance and
-- hence cannot use the regular box functions, or when you want to
-- send messages anonymously.
--
-- The "Crypto.Saltine.Core.Box" module is not meant to provide
-- non-repudiation. On the contrary: the 'box' function
-- guarantees repudiability. A receiver can freely modify a boxed
-- message, and therefore cannot convince third parties that this
-- particular message came from the sender. The sender and receiver
-- are nevertheless protected against forgeries by other parties. In
-- the terminology of
-- <http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c>,
-- 'box' uses "public-key authenticators" rather than "public-key
-- signatures."
--
-- Users who want public verifiability (or receiver-assisted public
-- verifiability) should instead use signatures (or
-- signcryption). Signatures are documented in the
-- "Crypto.Saltine.Core.Sign" module.
--
-- "Crypto.Saltine.Core.Box" is @curve25519xsalsa20poly1305@, a
-- particular combination of Curve25519, Salsa20, and Poly1305
-- specified in "Cryptography in NaCl"
-- (<http://nacl.cr.yp.to/valid.html>). This function is conjectured
-- to meet the standard notions of privacy and third-party
-- unforgeability.
--
-- This is version 2010.08.30 of the box.html web page.
module Crypto.Saltine.Core.Box (
  U.SecretKey, U.PublicKey, U.Keypair, U.CombinedKey,
  U.newKeypair, U.derivePublicKey, U.beforeNM,
  box, boxOpen,
  boxAfterNM, boxOpenAfterNM,
  U.boxSeal, U.boxSealOpen
  ) where

import           Crypto.Saltine.Class
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Unsafe.Box         as U

import qualified Data.ByteArray                    as B
import           Data.ByteString                     (ByteString)

-- | Encrypts a message for sending to the owner of the public
-- key. They must have your public key in order to decrypt the
-- message. It is infeasible for an attacker to decrypt the message
-- as a random nonce is prepended to the ciphertext.
box :: U.PublicKey
    -> U.SecretKey
    -> ByteString
    -- ^ Message
    -> IO ByteString
    -- ^ Ciphertext (incl. authentication tag)
box pk sk msg = do
  nonce <- U.newNonce
  let ciphertext = U.box pk sk nonce msg
  return $ B.append (encode nonce) ciphertext

-- | Decrypts a message sent from the owner of the public key. They
-- must have encrypted it using your public key. Returns 'Nothing' if
-- the keys and message do not match.
boxOpen :: U.PublicKey
        -> U.SecretKey
        -> ByteString
        -- ^ Ciphertext (incl. authentication tag)
        -> Maybe ByteString
        -- ^ Message
boxOpen pk sk cipher = do
  let (n, c) = split Bytes.boxNonce cipher
  nonce <- decode n
  U.boxOpen pk sk nonce c

-- | 'box' using a 'CombinedKey' and thus faster.
boxAfterNM :: U.CombinedKey
           -> ByteString
           -- ^ Message
           -> IO ByteString
           -- ^ Ciphertext (incl. authentication tag)
boxAfterNM ck msg = do
  nonce <- U.newNonce
  let ciphertext = U.boxAfterNM ck nonce msg
  return $ B.append (encode nonce) ciphertext

-- | 'boxOpen' using a 'CombinedKey' and is thus faster.
boxOpenAfterNM :: U.CombinedKey
               -> ByteString
               -- ^ Ciphertext (incl. authentication tag)
               -> Maybe ByteString
               -- ^ Message
boxOpenAfterNM ck cipher = do
  let (n, c) = split Bytes.boxNonce cipher
  nonce <- decode n
  U.boxOpenAfterNM ck nonce c
