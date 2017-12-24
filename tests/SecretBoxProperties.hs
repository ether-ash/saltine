{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-orphans #-}

module SecretBoxProperties (
  testSecretBox
  ) where

import           Util
import           Crypto.Saltine.Core.SecretBox
import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.ByteSizes as Bytes

import qualified Data.ByteString                      as S
import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck (Property, (==>))
import           Test.QuickCheck.Arbitrary
import           Test.QuickCheck.Property               (ioProperty)


instance Arbitrary Key where
    arbitrary =
        do bs <- S.pack <$> vector Bytes.secretBoxKey
           maybe (fail "impossible arbitrary failure.") pure (decode bs)
instance Show Key where
    show = show . encode

-- | Ciphertext can be decrypted
rightInverseProp :: Key -> Message -> IO Bool
rightInverseProp k (Message bs) = do
  c <- secretbox k bs
  return $ Just bs == secretboxOpen k c

-- | Detached ciphertext/tag can be decrypted
rightInverseDetachedProp :: Key -> Message -> IO Bool
rightInverseDetachedProp k (Message bs) = do
  (t, c) <- secretboxDetached k bs
  return $ Just bs == secretboxOpenDetached k t c

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureProp :: Key -> Message -> Perturb -> IO Bool
rightInverseFailureProp k (Message bs) p = do
  ct <- secretbox k bs
  let fakeCT = perturb ct p
  return $ ct == fakeCT || Nothing == secretboxOpen k fakeCT

-- | Ciphertext cannot be decrypted if the tag is perturbed
rightInverseTagFailureProp :: Key -> Message -> Message -> IO Bool
rightInverseTagFailureProp k (Message bs) (Message fakeTag) = do
  (realTag, ct) <- secretboxDetached k bs
  return $ realTag == fakeTag || Nothing == secretboxOpenDetached k fakeTag ct

-- | Ciphertext cannot be decrypted if the ciphertext is perturbed
rightInverseFailureDetachedProp :: Key -> Message -> Perturb -> IO Bool
rightInverseFailureDetachedProp k (Message bs) p = do
  (tag,ct) <- secretboxDetached k bs
  let fakeCT = perturb ct p
  return $ fakeCT == ct || Nothing == secretboxOpenDetached k tag fakeCT

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyProp :: Key -> Key -> Message -> IO Bool
cannotDecryptKeyProp k1 k2 (Message bs) = do
  c <- secretbox k1 bs
  return $ k1 == k2 || Nothing == secretboxOpen k2 c

-- | Ciphertext cannot be decrypted with a different key
cannotDecryptKeyDetachedProp :: Key -> Key -> Message -> IO Bool
cannotDecryptKeyDetachedProp k1 k2 (Message bs) = do
  (t, c) <- secretboxDetached k1 bs
  return $ k1 == k2 || Nothing == secretboxOpenDetached k2 t c

testSecretBox :: Test
testSecretBox = buildTest $ do

  return $ testGroup "...Core.SecretBox" [

    testProperty "Can decrypt ciphertext"
    $ ioProperty . uncurry rightInverseProp,

    testProperty "Can decrypt ciphertext (detached)"
    $ ioProperty . uncurry rightInverseDetachedProp,

    testGroup "Cannot decrypt ciphertext when..." [

      testProperty "... ciphertext is perturbed"
      $ ioProperty . uncurry2 rightInverseFailureProp,

      testProperty "... ciphertext is perturbed (detached)"
      $ ioProperty . uncurry2 rightInverseFailureDetachedProp,

      testProperty "... tag is perturbed (detached)"
      $ ioProperty . uncurry2 rightInverseTagFailureProp,

      testProperty "... using the wrong key"
      $ ioProperty . uncurry2 cannotDecryptKeyProp,

      testProperty "... using the wrong key (detached)"
      $ ioProperty . uncurry2 cannotDecryptKeyDetachedProp

      ]
    ]
