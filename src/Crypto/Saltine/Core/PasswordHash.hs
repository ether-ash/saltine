-- |
-- Module      : Crypto.Saltine.Core.PasswordHash
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Hashing: "Crypto.Saltine.Core.PasswordHash"
--
-- The 'pwHash' function takes a password the maximum number of
-- operations and the amount of ram and returns a hash. Hashes are
-- always of length 'Bytes.passWord'.
--
-- 'pwHash' is currently an implementation of argon2.
module Crypto.Saltine.Core.PasswordHash (
  pwHashStr
  ) where

import Crypto.Saltine.Class
import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import Control.Applicative
import Foreign.C
import Foreign.Ptr
import qualified Data.ByteString as B


pwHashStr :: B.ByteString
          -- ^ Password
          -> Int
          -- ^ Maximum number of operations to perform
          -> Int
          -- ^ Maximum amount of RAM the function will use
          -> B.ByteString
pwHashStr pass ops mem =
  snd . buildUnsafeCVector Bytes.passwordHash
    $ \ph -> constVectors [pass] $ \[(pm, _)] ->
      c_pwhash_str ph
        pm (fromIntegral $ B.length pass)
        (fromIntegral ops) (fromIntegral mem)

foreign import ccall "crypto_pwhash"
  c_pwhash :: Ptr CChar
           -- ^ Output key buffer
           -> CULLong
           -- ^ Key buffer length
           -> Ptr CChar
           -- ^ Constanct password buffer
           -> CULLong
           -- ^ Constant password buffer length
           -> Ptr CChar
           -- ^ Salt buffer
           -> CULLong
           -- ^ Maximum number of operations to perform
           -> CSize
           -- ^ Maximum amount of RAM the function will use
           -> IO Int
           -- ^ 0 on success, -1 for failure

foreign import ccall "crypto_pwhash_str"
  c_pwhash_str :: Ptr CChar
               -- ^ Output hash buffer
               -> Ptr CChar
               -- ^ Constant password buffer
               -> CULLong
               -- ^ Password buffer length
               -> CULLong
               -- ^ Maximum number of operations to perform
               -> CSize
               -- ^ Maximum amount of RAM the function will use
               -> IO Int
               -- ^ 0 on success, -1 on failure
