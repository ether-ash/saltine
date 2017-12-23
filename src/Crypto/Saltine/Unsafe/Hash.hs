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
generichash m len k
  | Bytes.generichashMin <= len && len <= Bytes.generichashMax
  = generichashInternal m len k
  | otherwise
  = error $ "incorrect length: " ++ show len ++ ", should be between "
    ++ show Bytes.generichashMin ++ " and " ++ show Bytes.generichashMax

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
newGenerichashKey :: IO GenerichashKey
newGenerichashKey = GhK <$> randomByteString Bytes.generichashKey


generichashInternal :: ByteString
                    -> Int
                    -> Maybe GenerichashKey
                    -> ByteString
generichashInternal m len (Just (GhK k)) =
  snd . buildUnsafeByteString len $ \ph ->
    constByteStrings [k, m] $ \[(pk, _), (pm, _)] ->
      c_generichash ph (fromIntegral len)
                    pm (fromIntegral $ S.length m)
                    pk (fromIntegral $ S.length k)
generichashInternal m len Nothing =
  snd . buildUnsafeByteString len $ \ph ->
    constByteStrings [m] $ \[(pm, _)] ->
      c_generichash ph (fromIntegral len)
                    pm (fromIntegral $ S.length m)
                    nullPtr 0


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
                -- ^ _
