{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module KeyExchangeProperties (
  testKeyExchange
  ) where

import           Util
import           Crypto.Saltine.Class
import           Crypto.Saltine.Core.AEAD          as AEAD
import           Crypto.Saltine.Core.SecretBox     as SecretBox
import           Crypto.Saltine.Internal.ByteSizes as Bytes
import           Crypto.Saltine.Unsafe.KeyExchange as Kx

import           Control.Monad           (replicateM)
import qualified Data.ByteString                      as S
import           Data.Maybe (fromJust)
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck (Property, (==>))
import           Test.QuickCheck.Arbitrary


instance Arbitrary Kx.Seed where
  arbitrary = fromJust . decode . S.pack <$> replicateM Bytes.kxSeed arbitrary
instance Show Kx.Seed where
  show = show . encode

instance Arbitrary AEAD.Nonce where
  arbitrary = fromJust . decode . S.pack <$> replicateM Bytes.secretBoxNonce arbitrary
instance Show AEAD.Nonce where
  show = show . encode

instance Arbitrary SecretBox.Nonce where
  arbitrary = fromJust . decode . S.pack <$> replicateM Bytes.secretBoxNonce arbitrary
instance Show SecretBox.Nonce where
  show = show . encode

matches :: Maybe SessionKeys -> Maybe SessionKeys -> Bool
matches Nothing Nothing = True
matches (Just clientKeys) (Just serverKeys) =
  encode clientKeys == S.append (S.drop 32 $ encode serverKeys) (S.take 32 $ encode serverKeys)
matches _ _ = False

testKeyExchange :: Test
testKeyExchange = buildTest $ do
  staticClient@(_clientSecretKey, clientPublicKey) <- newKeypair
  staticServer@(_serverSecretKEy, serverPublicKey) <- newKeypair

  return $ testGroup "...Internal.KeyExchange" [

    testProperty "client and server arrive at matching session keys"
    $ clientSessionKeys staticClient serverPublicKey `matches` serverSessionKeys staticServer clientPublicKey,

    testProperty "key exchange keys can be derived from seed"
    $ \clientSeed serverSeed ->
        let client@(_csk, cpk) = seedKeypair clientSeed
            server@(_ssk, spk) = seedKeypair serverSeed
        in clientSessionKeys client spk `matches` serverSessionKeys server cpk,

    testProperty "client can send secret box to server"
    $ \(Message m) nonce -> m /= S.empty ==>
        let Just clientKeys = clientSessionKeys staticClient serverPublicKey
            Just serverKeys = serverSessionKeys staticServer clientPublicKey
            ciphertext = kxSecretbox clientKeys nonce m
        in kxSecretboxOpen serverKeys nonce ciphertext == Just m,

    testProperty "server can send secret box to client"
    $ \(Message m) nonce -> m /= S.empty ==>
        let Just clientKeys = clientSessionKeys staticClient serverPublicKey
            Just serverKeys = serverSessionKeys staticServer clientPublicKey
            ciphertext = kxSecretbox serverKeys nonce m
        in kxSecretboxOpen clientKeys nonce ciphertext == Just m,

    testProperty "client can send aead to server"
    $ \(Message m) (Message aad) nonce ->
        let Just clientKeys = clientSessionKeys staticClient serverPublicKey
            Just serverKeys = serverSessionKeys staticServer clientPublicKey
            ciphertext = kxAead clientKeys nonce m aad
        in kxAeadOpen serverKeys nonce ciphertext aad == Just m,

    testProperty "server can send aead to client"
    $ \(Message m) (Message aad) nonce ->
        let Just clientKeys = clientSessionKeys staticClient serverPublicKey
            Just serverKeys = serverSessionKeys staticServer clientPublicKey
            ciphertext = kxAead serverKeys nonce m aad
        in kxAeadOpen clientKeys nonce ciphertext aad == Just m

    ]
