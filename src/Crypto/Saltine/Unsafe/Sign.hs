module Crypto.Saltine.Unsafe.Sign (
  Seed,
  deriveKeypair,
  derivePublicKey
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Core.Sign
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import           Foreign.C
import           Foreign.Ptr
import           Foreign.Marshal.Alloc
import           Foreign.Storable
import           System.IO.Unsafe
import qualified Data.ByteArray                    as B
import           Data.ByteArray                      (ByteArrayAccess, ByteArray, Bytes, ScrubbedBytes)
import qualified Data.ByteString                   as S
import           Data.ByteString                     (ByteString)
import           Data.Maybe                          (fromJust)

newtype Seed = Seed ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding Seed where
  decode v = if B.length v == Bytes.signSeed
           then Just (Seed $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (Seed v) = B.convert v
  {-# INLINE encode #-}

deriveKeypair :: Seed -> Keypair
deriveKeypair (Seed s) = unsafePerformIO $ do
  ((_err, sk), pk) <- buildUnsafeByteArray' Bytes.signPK $ \pkbuf ->
    buildUnsafeByteArray' Bytes.signSK $ \skbuf ->
      constByteArray s $ \ps ->
        c_sign_seed_keypair pkbuf skbuf ps
  -- XXX: unbelievably ugly solution but avoids
  --      need to expose keypair insides
  return (fromJust (decode sk), fromJust (decode pk))

derivePublicKey :: SecretKey -> PublicKey
derivePublicKey sk = fromJust $ decode $
  snd . buildUnsafeByteArray Bytes.signPK $ \pkbuf ->
    constByteArray (encode sk) $ \ps ->
      c_sign_ed25519_sk_to_pk pkbuf ps

foreign import ccall "crypto_sign_seed_keypair"
  c_sign_seed_keypair :: Ptr CChar
                      -- ^ Public key output buffer
                      -> Ptr CChar
                      -- ^ Secret key output buffer
                      -> Ptr CChar
                      -- ^ Constant seed buffer
                      -> IO CInt

foreign import ccall "crypto_sign_ed25519_sk_to_pk"
  c_sign_ed25519_sk_to_pk :: Ptr CChar
                          -- ^ Public key output buffer
                          -> Ptr CChar
                          -- ^ Constant secret key buffer
                          -> IO CInt
