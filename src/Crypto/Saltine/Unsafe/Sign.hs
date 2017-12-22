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
import qualified Data.ByteString                   as S
import           Data.ByteString                     (ByteString)
import           Data.Maybe                          (fromJust)

newtype Seed = Seed ByteString deriving (Eq, Ord)

instance IsEncoding Seed where
  decode v = if S.length v == Bytes.signSeed
           then Just (Seed v)
           else Nothing
  {-# INLINE decode #-}
  encode (Seed v) = v
  {-# INLINE encode #-}

deriveKeypair :: Seed -> Keypair
deriveKeypair (Seed s) = unsafePerformIO $ do
  ((_err, sk), pk) <- buildUnsafeByteString' Bytes.signPK $ \pkbuf ->
    buildUnsafeByteString' Bytes.signSK $ \skbuf ->
      constByteStrings [s] $ \[(ps, _)] ->
        c_sign_seed_keypair pkbuf skbuf ps
  -- XXX: unbelievably ugly solution but avoids
  --      need to expose keypair insides
  return (fromJust (decode sk), fromJust (decode pk))

derivePublicKey :: SecretKey -> PublicKey
derivePublicKey sk = fromJust $ decode $
  snd . buildUnsafeByteString Bytes.signPK $ \pkbuf ->
    constByteStrings [encode sk] $ \[(ps, _)] ->
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
