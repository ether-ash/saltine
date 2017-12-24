{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE OverloadedLists #-}

module BoxProperties (
  testBox
  ) where

import           Util
import           Crypto.Saltine.Class
import           Crypto.Saltine.Core.Box
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import qualified Data.ByteString                      as S
import           Data.Monoid

import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck.Property
import           Test.QuickCheck.Monadic
import           Test.QuickCheck.Property               (ioProperty)

-- | Ciphertext can be decrypted
rightInverseProp :: Keypair -> Keypair -> Message -> IO Bool
rightInverseProp (sk1, pk1) (sk2, pk2) (Message bs) = do
  c <- box pk2 sk1 bs
  return $ Just bs == boxOpen pk1 sk2 c

-- | Cannot decrypt without the corrent secret key
rightInverseFailureProp1 :: Keypair -> Keypair -> Message -> Perturb -> IO Bool
rightInverseFailureProp1 (sk1, pk1) (sk2, pk2) (Message bs) p = do
  c <- box pk2 sk1 bs
  return $ Nothing == boxOpen pk1 (perturb sk2 ([0] <> p)) c

-- | Cannot decrypt when not sent to you
rightInverseFailureProp2 :: Keypair -> Keypair -> Message -> Perturb -> IO Bool
rightInverseFailureProp2 (sk1, pk1) (sk2, pk2) (Message bs) p = do
  c <- box (perturb pk2 p) sk1 bs
  return $ Nothing == boxOpen pk1 sk2 c

-- | Ciphertext cannot be decrypted (verification failure) if the
-- ciphertext is perturbed
rightInverseFailureProp3 :: Keypair -> Keypair -> Message -> Perturb -> IO Bool
rightInverseFailureProp3 (sk1, pk1) (sk2, pk2) (Message bs) p = do
  c <- box pk2 sk1 bs
  return $ Nothing == boxOpen pk1 sk2 (perturb c p)

-- | Ciphertext can be decrypted using combined keys
rightInverseAfterNMProp
  :: CombinedKey -> CombinedKey -> Message -> IO Bool
rightInverseAfterNMProp ck_1for2 ck_2for1 (Message bs) = do
  c <- boxAfterNM ck_1for2 bs
  return $ Just bs == boxOpenAfterNM ck_2for1 c

-- | Perturbed ciphertext cannot be decrypted using combined keys
rightInverseFailureAfterNMProp1
  :: CombinedKey -> CombinedKey -> Message -> Perturb -> IO Bool
rightInverseFailureAfterNMProp1 ck_1for2 ck_2for1 (Message bs) p = do
  c <- boxAfterNM ck_1for2 bs
  return $ Nothing == boxOpenAfterNM ck_2for1 (perturb c p)

testBox :: Test
testBox = buildTest $ do
  (sk1, pk1) <- newKeypair
  (sk2, pk2) <- newKeypair
  let ck_1for2 = beforeNM sk1 pk2
      ck_2for1 = beforeNM sk2 pk1

  return $ testGroup "...Internal.Box" [

    testGroup "Can decrypt ciphertext using..." [

       testProperty "... public key/secret key"
       $ ioProperty . rightInverseProp (sk1, pk1) (sk2, pk2),

       testProperty "... combined key"
       $ ioProperty . rightInverseAfterNMProp ck_1for2 ck_2for1

       ],

    testGroup "Fail to verify ciphertext when..." [

      testProperty "... not using proper secret key"
      $ ioProperty . uncurry (rightInverseFailureProp1 (sk1, pk1) (sk2, pk2)),

      testProperty "... not actually sent to you"
      $ ioProperty . uncurry (rightInverseFailureProp2 (sk1, pk1) (sk2, pk2)),

      testProperty "... ciphertext has been perturbed"
      $ ioProperty . uncurry (rightInverseFailureProp3 (sk1, pk1) (sk2, pk2)),

      testProperty "... using the wrong combined key"
      $ ioProperty . uncurry (rightInverseFailureAfterNMProp1 ck_1for2 ck_2for1)

      ]
    ]
