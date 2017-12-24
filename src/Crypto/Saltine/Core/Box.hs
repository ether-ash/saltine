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
-- Distinct messages between the same @{sender, receiver}@ set are
-- required to have distinct nonces. For example, the
-- lexicographically smaller public key can use nonce 1 for its first
-- message to the other key, nonce 3 for its second message, nonce 5
-- for its third message, etc., while the lexicographically larger
-- public key uses nonce 2 for its first message to the other key,
-- nonce 4 for its second message, nonce 6 for its third message,
-- etc. Nonces are long enough that randomly generated nonces have
-- negligible risk of collision.
--
-- There is no harm in having the same nonce for different messages if
-- the @{sender, receiver}@ sets are different. This is true even if
-- the sets overlap. For example, a sender can use the same nonce for
-- two different messages if the messages are sent to two different
-- public keys.
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
-- non-repudiation. On the contrary: the crypto_box function
-- guarantees repudiability. A receiver can freely modify a boxed
-- message, and therefore cannot convince third parties that this
-- particular message came from the sender. The sender and receiver
-- are nevertheless protected against forgeries by other parties. In
-- the terminology of
-- <http://groups.google.com/group/sci.crypt/msg/ec5c18b23b11d82c>,
-- crypto_box uses "public-key authenticators" rather than "public-key
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
  U.SecretKey, U.PublicKey, U.Keypair, U.CombinedKey, U.Nonce,
  U.newKeypair, U.beforeNM, U.newNonce,
  U.box, U.boxOpen,
  U.boxAfterNM, U.boxOpenAfterNM,
  U.boxSeal, U.boxSealOpen
  ) where

import qualified Crypto.Saltine.Unsafe.Box as U
