module Crypto.Saltine.Unsafe.Hash (
  GenerichashKey,
  generichash,
  newGenerichashKey
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import           Control.Applicative
import           Foreign.C
import           Foreign.Ptr
import qualified Data.ByteArray                    as B
import           Data.ByteArray                      (ByteArrayAccess, ByteArray, Bytes, ScrubbedBytes)
import qualified Data.ByteString                   as S
import           Data.ByteString                     (ByteString)

-- | Computes a fixed-length fingerprint for an arbitrary long
-- message using an optional key.
generichash :: ByteString
            -- ^ Message
            -> Int
            -- ^ Length of output
            -> Maybe GenerichashKey
            -- ^ Optional key
            -> ByteString
generichash m len Nothing        = generichash' m len B.empty
generichash m len (Just (GhK k)) = generichash' m len k

-- | An opaque 'generichashKeyed' cryptographic secret key.
newtype GenerichashKey = GhK ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding GenerichashKey where
  decode v = if B.length v >= Bytes.generichashKeyMin && S.length v <= Bytes.generichashKeyMax
           then Just (GhK $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (GhK v) = B.convert v
  {-# INLINE encode #-}

-- | Randomly generates a new key for 'generichash'.
newGenerichashKey :: Int -> IO GenerichashKey
newGenerichashKey len
  | Bytes.generichashKeyMin <= len && len <= Bytes.generichashKeyMax
  = GhK <$> randomByteArray len
  | otherwise
  = lengthError len Bytes.generichashKeyMin Bytes.generichashKeyMax

generichash' :: ByteString
             -> Int
             -> ScrubbedBytes
             -> ByteString
generichash' m len k
  | Bytes.generichashMin <= len && len <= Bytes.generichashMax
  = snd . buildUnsafeByteArray len $ \ph ->
      constByteArray2 k m $ \pk pm ->
        c_generichash ph (fromIntegral len) pm (fromIntegral $ S.length m) pk (fromIntegral $ B.length k)
  | otherwise
  = lengthError len Bytes.generichashMin Bytes.generichashMax

lengthError :: Int -> Int -> Int -> a
lengthError len atLeast atMost =
  error $ "incorrect length: " ++ show len ++ ", should be between " ++ show atLeast ++ " and " ++ show atMost

foreign import ccall "crypto_generichash"
  c_generichash :: Ptr CChar
                -- ^ Output hash buffer
                -> CSize
                -- ^ Output buffer length
                -> Ptr CChar
                -- ^ Constant message buffer
                -> CULLong
                -- ^ Message buffer length
                -> Ptr CChar
                -- ^ Constant key buffer
                -> CSize
                -- ^ Key buffer length
                -> IO CInt
