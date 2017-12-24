-- |
-- Module      : Crypto.Saltine.Core.Sign
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Signatures: "Crypto.Saltine.Core.Sign"
--
-- The 'newKeypair' function randomly generates a secret key and a
-- corresponding public key. The 'sign' function signs a message
-- 'ByteString' using the signer's secret key and returns the
-- resulting signed message. The 'signOpen' function verifies the
-- signature in a signed message using the signer's public key then
-- returns the message without its signature.
--
-- "Crypto.Saltine.Core.Sign" is an EdDSA signature using
-- elliptic-curve Curve25519 (see: <http://ed25519.cr.yp.to/>). See
-- also, \"Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter
-- Schwabe, Bo-Yin Yang. High-speed high-security signatures. Journal
-- of Cryptographic Engineering 2 (2012), 77–89.\"
-- <http://ed25519.cr.yp.to/ed25519-20110926.pdf>.
--
-- This is current information as of 2013 June 6.

module Crypto.Saltine.Core.Sign (
  U.SecretKey, U.PublicKey, U.Keypair,
  U.newKeypair,
  U.sign, U.signOpen,
  U.signDetached, U.signVerifyDetached
  ) where

import qualified Crypto.Saltine.Unsafe.Sign as U
