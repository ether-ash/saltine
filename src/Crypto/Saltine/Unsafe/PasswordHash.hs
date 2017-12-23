{-# LANGUAGE RecordWildCards #-}
-- |
-- Module      : Crypto.Saltine.Unsafe.PasswordHash
-- Copyright   : (c) Joseph Abrahamson 2013
-- License     : MIT
--
-- Maintainer  : me@jspha.com
-- Stability   : experimental
-- Portability : non-portable
--
-- Password Hashing: "Crypto.Saltine.Unsafe.PasswordHash"
--
-- The 'pwhash' function takes a password 'ByteString', a salt 'Salt',
-- which can be generated using 'genSalt', and a hashing policy
-- consisting of the maximum numnber of computations and the maximum
-- number of memory the function is allowed to use.
-- The 'pwhashStr' function takes a password the maximum number of
-- operations and the amount of ram and returns a hash. Hashes are
-- always of length 'Bytes.passWord'.
-- The pwhashVerify function takes a password 'ByteString' and an
-- encrypted password as returned by pwhashStr and checks if it's the
-- hashed password.
--
-- "Crypto.Saltine.Unsafe.PasswordHash" is currently a implementation of
-- Argon2.
--
-- This is version 2016.03.20 of the passwordhash.html web page.
module Crypto.Saltine.Unsafe.PasswordHash (
  HashingPolicy(..),
  EncryptedPass(..),
  Salt(..),
  interactivePolicy,
  moderatePolicy,
  sensitivePolicy,
  genSalt,
  pwhash,
  pwhashStr,
  pwhashStrVerify
  ) where

import Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes

import System.IO.Unsafe
import Foreign.Marshal.Alloc
import Foreign.C
import Foreign.Ptr
import qualified Data.ByteString as B

-- $types

-- | Encapsulates the tuning values for the c_pwhash functions
data HashingPolicy = HashingPolicy
  { opsLimit :: Int
  -- ^ Maximum amount of computations to perform.
  -- Raising this number will make the function require more CPU cycles
  -- to compute a key.
  , memLimit :: Int
  -- ^ Maximum amount of RAM that the function will use, in bytes.
  -- It is highly recommended to allow the function to use at least 16
  -- megabytes.
  }

-- | A policy for highly sensitive data. It should be noted that deriving
-- a key with this policy takes about 2 seconds on a 2.8 Ghz Core i7 CPU
-- and requires up to 1 gigabyte of dedicated RAM.
sensitivePolicy :: HashingPolicy
sensitivePolicy = HashingPolicy
  { opsLimit = Bytes.opslimitSensitive
  , memLimit = Bytes.memlimitSensitive
  }

-- | A policy for moderately sensitive data. Somewhere between sensitivePolicy
-- and interactivePolicy
moderatePolicy :: HashingPolicy
moderatePolicy = HashingPolicy
  { opsLimit = Bytes.opslimitModerate
  , memLimit = Bytes.memlimitModerate
  }

-- | A policy for interactive, online operations. Safe base line for the
-- parameters, for more sensitive data it's recommended to use higher
-- values
interactivePolicy :: HashingPolicy
interactivePolicy = HashingPolicy
  { opsLimit = Bytes.opslimitInteractive
  , memLimit = Bytes.memlimitInteractive
  }

-- | ASCII encoded String containing the result of the
-- hash function, the automatically generated salt and the two parameters
-- opslimit and memlimit.
newtype EncryptedPass = EP B.ByteString deriving Show

-- | Randomly Generated Salt with a length of 'Bytes.salt'
newtype Salt = Salt {salt :: B.ByteString}

-- | Generates new random salt
genSalt :: IO Salt
genSalt = do
  salt <- randomByteString Bytes.salt
  return Salt{..}

-- | Derives a key from a password and a salt salt.
-- If 'Int' <= 16 the function returns a 16 Bytes long 'ByteString' of \Null
pwhash :: Int
       -- ^ Length of resulting key
       -> B.ByteString
       -- ^ Password
       -> Salt
       -- ^ Salt
       -> HashingPolicy
       -- ^ used HashingPolicy
       -> B.ByteString
pwhash keyLen pass Salt{..} HashingPolicy{..} =
  unsafePerformIO $
    B.useAsCStringLen pass $ \(passPtr, passLen) ->
    B.useAsCString salt $ \saltPtr ->
    allocaBytes (fromIntegral keyLen) $ \buf -> do
      throwErrnoIfMinus1_ "crypto_pwhash_str" $
        c_pwhash buf (fromIntegral keyLen) passPtr (fromIntegral passLen)
          saltPtr (fromIntegral opsLimit) (fromIntegral memLimit)
      B.packCString $ castPtr buf

-- | Computes an ASCII encoded string containing the result of the
-- hash function, the automatically generated salt and the two parameters
-- opslimit and memlimit.
--
-- The output string is zero-terminated, includes only ASCII characters
-- and can be safely stored into SQL databases and other data stores.
-- No extra information has to be stored in order to verify the password.
pwhashStr :: B.ByteString
          -- ^ Password
          -> HashingPolicy
          -- ^ used HashingPolicy
          -> EncryptedPass
pwhashStr pass HashingPolicy{..} =
  EP $ unsafePerformIO $
    B.useAsCStringLen pass $ \(passPtr, passLen) ->
    allocaBytes (fromIntegral Bytes.passwordHash) $ \buf -> do
            throwErrnoIfMinus1_ "crypto_pwhash_str" $
              c_pwhash_str buf passPtr (fromIntegral passLen)
                (fromIntegral opsLimit) (fromIntegral memLimit)
            B.packCString
              (castPtr buf)

-- | This function verifies that the string ,'EncryptedPass', is a valid
-- password verification string (as generated by pwhashStr for passwd
-- 'ByteString'.
pwhashStrVerify :: B.ByteString
                -- ^ Password
                -> EncryptedPass
                -- ^ Encrypted password string
                -> Bool
pwhashStrVerify pass (EP ePass) =
  unsafePerformIO $ do
    res <- verify
    if res == 0
      then return True
      else return False
    where
      verify = B.useAsCString ePass $ \epPtr ->
        B.useAsCStringLen pass $ \(pPtr, pLen) ->
        return $ c_pwhash_str_verify epPtr pPtr (fromIntegral pLen)

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
           -- ^ Constant Salt buffer
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

-- | We don't even include this in the IO monad since all of the
-- buffers are constant.
foreign import ccall "crypto_pwhash_str_verify"
  c_pwhash_str_verify :: Ptr CChar
                      -- ^ Constant hash string buffer as returned
                      -- from pwhashStr
                      -> Ptr CChar
                      -- ^ Constant password buffer
                      -> CULLong
                      -- ^ Password buffer length
                      -> CInt
                      -- ^ 0 on success, -1 on failure
