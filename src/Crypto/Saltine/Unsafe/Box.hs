module Crypto.Saltine.Unsafe.Box (
  Seed,
  deriveKeypair,
  derivePublicKey
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Core.Box
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes
import           Crypto.Saltine.Unsafe.ScalarMult

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
  decode v = if S.length v == Bytes.boxSeed
           then Just (Seed v)
           else Nothing
  {-# INLINE decode #-}
  encode (Seed v) = v
  {-# INLINE encode #-}

deriveKeypair :: Seed -> Keypair
deriveKeypair (Seed s) = unsafePerformIO $ do
  ((_err, sk), pk) <- buildUnsafeByteString' Bytes.boxPK $ \pkbuf ->
    buildUnsafeByteString' Bytes.boxSK $ \skbuf ->
      constByteStrings [s] $ \[(ps, _)] ->
        c_box_seed_keypair pkbuf skbuf ps
  -- XXX: unbelievably ugly solution but avoids
  --      need to expose keypair insides
  return (fromJust (decode sk), fromJust (decode pk))

derivePublicKey :: SecretKey -> PublicKey
derivePublicKey sk =
  fromJust $ decode $ encode $ multBase $ fromJust $ decode $ encode sk

foreign import ccall "crypto_box_seed_keypair"
  c_box_seed_keypair :: Ptr CChar
                     -- ^ Public key output buffer
                     -> Ptr CChar
                     -- ^ Secret key output buffer
                     -> Ptr CChar
                     -- ^ Constant seed buffer
                     -> IO CInt
