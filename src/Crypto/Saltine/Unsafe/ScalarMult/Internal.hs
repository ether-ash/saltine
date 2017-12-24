module Crypto.Saltine.Unsafe.ScalarMult.Internal (
  c_scalarmult, c_scalarmult_base
  ) where


import           Foreign.C
import           Foreign.Ptr

foreign import ccall "crypto_scalarmult"
  c_scalarmult :: Ptr CChar
               -- ^ Output group element buffer
               -> Ptr CChar
               -- ^ Input integer buffer
               -> Ptr CChar
               -- ^ Input group element buffer
               -> IO CInt
               -- ^ Always 0

-- | Ugly hack to expose the raw C function for "Crypto.Saltine.Unsafe.Box"
foreign import ccall "crypto_scalarmult_base"
  c_scalarmult_base :: Ptr CChar
                    -- ^ Output group element buffer
                    -> Ptr CChar
                    -- ^ Input integer buffer
                    -> IO CInt
                    -- ^ Always 0
