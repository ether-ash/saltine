{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE OverloadedLists #-}

module BoxProperties (
  testBox
  ) where

import           Util
import           Crypto.Saltine.Class
import           Crypto.Saltine.Core.Box
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes
import           Crypto.Saltine.Unsafe.Box

import qualified Data.ByteString                      as S
import           Data.Monoid

import           Test.Framework.Providers.QuickCheck2
import           Test.Framework
import           Test.QuickCheck.Property
import           Test.QuickCheck.Monadic

-- | Ciphertext can be decrypted
rightInverseProp :: Keypair -> Keypair -> Nonce -> Message -> Bool
rightInverseProp (sk1, pk1) (sk2, pk2) n (Message bs) =
  Just bs == boxOpen pk1 sk2 n (box pk2 sk1 n bs)

-- | Cannot decrypt without the corrent secret key
rightInverseFailureProp1 :: Keypair -> Keypair -> Nonce -> Message -> Perturb -> Bool
rightInverseFailureProp1 (sk1, pk1) (sk2, pk2) n (Message bs) p =
  Nothing == boxOpen pk1 (perturb sk2 ([0] <> p)) n (box pk2 sk1 n bs)

-- | Cannot decrypt when not sent to you
rightInverseFailureProp2 :: Keypair -> Keypair -> Nonce -> Message -> Perturb -> Bool
rightInverseFailureProp2 (sk1, pk1) (sk2, pk2) n (Message bs) p =
  Nothing == boxOpen pk1 sk2 n (box (perturb pk2 p) sk1 n bs)

-- | Ciphertext cannot be decrypted (verification failure) if the
-- ciphertext is perturbed
rightInverseFailureProp3 :: Keypair -> Keypair -> Nonce -> Message -> Perturb -> Bool
rightInverseFailureProp3 (sk1, pk1) (sk2, pk2) n (Message bs) p =
  Nothing == boxOpen pk1 sk2 n (perturb (box pk2 sk1 n bs) p)

-- | Ciphertext cannot be decrypted with a different nonce
cannotDecryptNonceProp
  :: Keypair -> Keypair -> Nonce -> Nonce -> Message -> Bool
cannotDecryptNonceProp (sk1, pk1) (sk2, pk2) n1 n2 (Message bs) =
  Nothing == boxOpen pk1 sk2 n2 (box pk2 sk1 n1 bs)

-- | BeforeNM creates identical secret keys when called in an
-- anti-symmetric fashion.
beforeNMCreateSecretKeyProp :: Test.QuickCheck.Property.Property
beforeNMCreateSecretKeyProp = monadicIO . (assert =<<) . run $ do
  (sk1, pk1) <- newKeypair
  (sk2, pk2) <- newKeypair
  let ck_1for2 = beforeNM sk1 pk2
      ck_2for1 = beforeNM sk2 pk1
  return (ck_1for2 == ck_2for1)

-- | Ciphertext can be decrypted using combined keys
rightInverseAfterNMProp
  :: CombinedKey -> CombinedKey -> Nonce -> Message -> Bool
rightInverseAfterNMProp ck_1for2 ck_2for1 n (Message bs) =
  Just bs == boxOpenAfterNM ck_2for1 n (boxAfterNM ck_1for2 n bs)

-- | Perturbed ciphertext cannot be decrypted using combined keys
rightInverseFailureAfterNMProp1
  :: CombinedKey -> CombinedKey -> Nonce -> Message -> Perturb -> Bool
rightInverseFailureAfterNMProp1 ck_1for2 ck_2for1 n (Message bs) p =
  Nothing == boxOpenAfterNM ck_2for1 n (perturb (boxAfterNM ck_1for2 n bs) p)

-- | Valid keys can be derived from seed
deriveKeypairProp
  :: Nonce -> ByteString32 -> ByteString32 -> Message -> Bool
deriveKeypairProp n (ByteString32 s1) (ByteString32 s2) (Message m) =
  let Just seed1 = decode $ S.take Bytes.boxSeed s1
      Just seed2 = decode $ S.take Bytes.boxSeed s2
      (sk1, pk1) = deriveKeypair seed1
      (sk2, pk2) = deriveKeypair seed2
  in Just m == boxOpen pk1 sk2 n (box pk2 sk1 n m)

derivePublicKeyProp
  :: ByteString32 -> Bool
derivePublicKeyProp (ByteString32 s) =
  let Just seed = decode $ S.take Bytes.boxSeed s
      (sk, pk) = deriveKeypair seed
  in pk == derivePublicKey sk

testBox :: Test
testBox = buildTest $ do
  (sk1, pk1) <- newKeypair
  (sk2, pk2) <- newKeypair
  let ck_1for2 = beforeNM sk1 pk2
      ck_2for1 = beforeNM sk2 pk1
  n1 <- newNonce
  n2 <- newNonce

  return $ testGroup "...Internal.Box" [

    testGroup "Can decrypt ciphertext using..." [

       testProperty "... public key/secret key"
       $ rightInverseProp (sk1, pk1) (sk2, pk2) n1 ,

       testProperty "... combined key"
       $ rightInverseAfterNMProp ck_1for2 ck_2for1 n1

       ],

    testGroup "Fail to verify ciphertext when..." [

      testProperty "... not using proper secret key"
      $ rightInverseFailureProp1 (sk1, pk1) (sk2, pk2) n1,

      testProperty "... not actually sent to you"
      $ rightInverseFailureProp2 (sk1, pk1) (sk2, pk2) n1,

      testProperty "... ciphertext has been perturbed"
      $ rightInverseFailureProp3 (sk1, pk1) (sk2, pk2) n1,

      testProperty "... using the wrong nonce"
      $ cannotDecryptNonceProp (sk1, pk1) (sk2, pk2) n1 n2,

      testProperty "... using the wrong combined key"
      $ rightInverseFailureAfterNMProp1 ck_1for2 ck_2for1 n1

      ],

    testGroup "(properties)" [

      testProperty "beforeNM is anti-symmetric" beforeNMCreateSecretKeyProp,

      testProperty "deriveKeypair works for all seeds" $ deriveKeypairProp n1,

      testProperty "derivePublicKey works for all secret keys" derivePublicKeyProp

      ]
    ]
