{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module AEADProperties (
  testAEAD
  ) where

import           Util
import           Crypto.Saltine.Core.AEAD
import           Crypto.Saltine.Class (decode,encode)
import           Crypto.Saltine.Internal.ByteSizes as Bytes

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck.Arbitrary
import           Test.QuickCheck.Property               (ioProperty)

instance Arbitrary Key where
    arbitrary =
        do bs <- S.pack <$> vector Bytes.secretBoxKey
           maybe (fail "impossible arbitrary failure.") pure (decode bs)

instance Show Key where
    show = show . encode

-- | Ciphertext can be decrypted
rightInverseProp :: Key -> Message -> Message -> IO Bool
rightInverseProp k (Message bs) (Message aad) = do
  c <- aead k bs aad
  return $ Just bs == aeadOpen k c aad

-- | Detached ciphertext/tag can be decrypted
rightInverseDetachedProp :: Key -> Message -> Message -> IO Bool
rightInverseDetachedProp k (Message bs) (Message aad) = do
  (tag,ct) <- aeadDetached k bs aad
  return $ Just bs == aeadOpenDetached k tag ct aad

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureProp :: Key -> Message -> Message -> Perturb -> IO Bool
rightInverseFailureProp k (Message bs) (Message aad) p = do
  ct <- aead k bs aad
  let fakeCT = perturb ct p
  return $ S.length bs == 0 || fakeCT == ct || Nothing == aeadOpen k fakeCT aad

-- | Ciphertext cannot be decrypted if the aad is perturbed
rightInverseAADFailureProp :: Key -> Message -> Message -> Message -> IO Bool
rightInverseAADFailureProp k (Message bs) (Message aad) (Message aad2) = do
  c <- aead k bs aad
  return $ aad == aad2 || Nothing == aeadOpen k c aad2

-- | Ciphertext cannot be decrypted if the tag is perturbed
rightInverseTagFailureProp :: Key -> Message -> Message -> Message -> IO Bool
rightInverseTagFailureProp k (Message bs) (Message aad) (Message newTag) = do
   (tag,ct) <- aeadDetached k bs aad
   return $ tag == newTag || Nothing == aeadOpenDetached k newTag ct aad

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureDetachedProp :: Key -> Message -> Message -> Perturb -> IO Bool
rightInverseFailureDetachedProp k (Message bs) (Message aad) p@(Perturb pBytes) = do
  (tag,ct) <- aeadDetached k bs aad
  return $ S.length bs <= length pBytes || Nothing == aeadOpenDetached k tag (perturb ct p) aad

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyProp :: Key -> Key -> Message -> Message -> IO Bool
cannotDecryptKeyProp k1 k2 (Message bs) (Message aad) = do
  ct <- aead k1 bs aad
  return $ k1 == k2 || Nothing == aeadOpen k2 ct aad

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyDetachedProp :: Key -> Key -> Message -> Message -> IO Bool
cannotDecryptKeyDetachedProp k1 k2 (Message bs) (Message aad) = do
  (tag,ct) <- aeadDetached k1 bs aad
  return $ k1 == k2 || Nothing == aeadOpenDetached k2 tag ct aad

testAEAD :: Test
testAEAD = buildTest $ do

  return $ testGroup "...Unsafe.AEAD" [

    testProperty "Can decrypt ciphertext"
    $ ioProperty . uncurry2 rightInverseProp,

    testProperty "Can decrypt ciphertext (detached)"
    $ ioProperty . uncurry2 rightInverseDetachedProp,

    testGroup "Cannot decrypt ciphertext when..." [

      testProperty "... ciphertext is perturbed"
      $ ioProperty . uncurry3 rightInverseFailureProp,

      testProperty "... AAD is perturbed"
      $ ioProperty . uncurry3 rightInverseAADFailureProp,

      testProperty "... ciphertext is perturbed (detached)"
      $ ioProperty . uncurry3 rightInverseFailureDetachedProp,

      testProperty "... tag is perturbed (detached)"
      $ ioProperty . uncurry3 rightInverseTagFailureProp,

      testProperty "... using the wrong key"
      $ ioProperty . uncurry3 cannotDecryptKeyProp,

      testProperty "... using the wrong key (detached)"
      $ ioProperty . uncurry3 cannotDecryptKeyDetachedProp

      ]
    ]
