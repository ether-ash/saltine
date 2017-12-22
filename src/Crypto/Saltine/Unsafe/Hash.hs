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
import qualified Data.ByteString as S
import           Data.ByteString (ByteString)

-- | Computes a fixed-length fingerprint for an arbitrary long
-- message using an optional key.
generichash :: ByteString
            -- ^ Message
            -> Int
            -- ^ Length of output
            -> Maybe GenerichashKey
            -- ^ Optional key
            -> ByteString
generichash m len Nothing        = generichashInternal m len S.empty
generichash m len (Just (GhK k)) = generichashInternal m len k

-- | An opaque 'generichashKeyed' cryptographic secret key.
newtype GenerichashKey = GhK ByteString deriving (Eq, Ord)

instance IsEncoding GenerichashKey where
  decode v = if S.length v >= Bytes.generichashKeyMin && S.length v <= Bytes.generichashKeyMax
           then Just (GhK v)
           else Nothing
  {-# INLINE decode #-}
  encode (GhK v) = v
  {-# INLINE encode #-}

-- | Randomly generates a new key for 'generichash'.
newGenerichashKey :: Int -> IO GenerichashKey
newGenerichashKey len
  | Bytes.generichashKeyMin <= len && len <= Bytes.generichashKeyMax
  = GhK <$> randomByteString len
  | otherwise
  = lengthError len Bytes.generichashKeyMin Bytes.generichashKeyMax

generichashInternal :: ByteString
                    -> Int
                    -> ByteString
                    -> ByteString
generichashInternal m len k
  | Bytes.generichashMin <= len && len <= Bytes.generichashMax
  = snd . buildUnsafeByteString len $ \ph ->
      constByteStrings [k, m] $ \[(pk, _), (pm, _)] ->
        c_generichash ph (fromIntegral len) pm (fromIntegral $ S.length m) pk (fromIntegral $ S.length k)
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
