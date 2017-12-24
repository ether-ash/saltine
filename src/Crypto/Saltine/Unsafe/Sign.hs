module Crypto.Saltine.Unsafe.Sign (
  SecretKey, PublicKey, Keypair, Seed,
  newKeypair, seedKeypair, derivePublicKey,
  sign, signOpen,
  signDetached, signVerifyDetached
  ) where

import           Crypto.Saltine.Class
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

-- $types

-- | An opaque 'sign' cryptographic secret key.
newtype SecretKey = SK ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding SecretKey where
  decode v = if B.length v == Bytes.signSK
           then Just (SK $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (SK v) = B.convert v
  {-# INLINE encode #-}

-- | An opaque 'sign' cryptographic public key.
newtype PublicKey = PK Bytes deriving (Eq, Ord)

instance IsEncoding PublicKey where
  decode v = if B.length v == Bytes.signPK
           then Just (PK $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (PK v) = B.convert v
  {-# INLINE encode #-}

-- | A convenience type for keypairs
type Keypair = (SecretKey, PublicKey)

-- | An opaque 'sign' cryptographic key seed
newtype Seed = Seed ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding Seed where
  decode v = if B.length v == Bytes.signSeed
           then Just (Seed $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (Seed v) = B.convert v
  {-# INLINE encode #-}


-- | Creates a random key of the correct size for 'sign' and
-- 'signOpen' of form @(secretKey, publicKey)@.
newKeypair :: IO Keypair
newKeypair = do
  -- This is a little bizarre and a likely source of errors.
  -- _err ought to always be 0.
  ((_err, sk), pk) <- buildUnsafeByteArray' Bytes.signPK $ \pkbuf ->
    buildUnsafeByteArray' Bytes.signSK $ \skbuf ->
      c_sign_keypair pkbuf skbuf
  return (SK sk, PK pk)

-- | Creates a deterministic key from a given seed
seedKeypair :: Seed -> Keypair
seedKeypair (Seed s) = unsafePerformIO $ do
  ((_err, sk), pk) <- buildUnsafeByteArray' Bytes.signPK $ \pkbuf ->
    buildUnsafeByteArray' Bytes.signSK $ \skbuf ->
      constByteArray s $ \ps ->
        c_sign_seed_keypair pkbuf skbuf ps
  return (SK sk, PK pk)

-- | Derives the corresponding public key from a given secret key
derivePublicKey :: SecretKey -> PublicKey
derivePublicKey (SK sk) = PK $
  snd . buildUnsafeByteArray Bytes.signPK $ \pkbuf ->
    constByteArray sk $ \psk ->
      c_sign_ed25519_sk_to_pk pkbuf psk

-- | Augments a message with a signature forming a \"signed
-- message\".
sign :: SecretKey
     -> ByteString
     -- ^ Message
     -> ByteString
     -- ^ Signed message
sign (SK k) m = unsafePerformIO $
  alloca $ \psmlen -> do
    (_err, sm) <- buildUnsafeByteArray' (len + Bytes.sign) $ \psmbuf ->
      constByteArray2 k m $ \pk pm ->
        c_sign psmbuf psmlen pm (fromIntegral len) pk
    smlen <- peek psmlen
    return $ S.take (fromIntegral smlen) sm
  where len = S.length m

-- | Checks a \"signed message\" returning 'Just' the original message
-- iff the signature was generated using the 'SecretKey' corresponding
-- to the given 'PublicKey'. Returns 'Nothing' otherwise.
signOpen :: PublicKey
         -> ByteString
         -- ^ Signed message
         -> Maybe ByteString
         -- ^ Maybe the restored message
signOpen (PK k) sm = unsafePerformIO $
  alloca $ \pmlen -> do
    (err, m) <- buildUnsafeByteArray' smlen $ \pmbuf ->
      constByteArray2 k sm $ \pk psm ->
        c_sign_open pmbuf pmlen psm (fromIntegral smlen) pk
    mlen <- peek pmlen
    case err of
      0 -> return $ Just $ S.take (fromIntegral mlen) m
      _ -> return   Nothing
  where smlen = S.length sm

-- | Returns just the signature for a message using a SecretKey.
signDetached :: SecretKey
             -> ByteString
             -- ^ Message
             -> ByteString
             -- ^ Signature
signDetached (SK k) m = unsafePerformIO $
  alloca $ \psmlen -> do
    (_err, sm) <- buildUnsafeByteArray' Bytes.sign $ \sigbuf ->
      constByteArray2 k m $ \pk pm ->
        c_sign_detached sigbuf psmlen pm (fromIntegral len) pk
    smlen <- peek psmlen
    return $ S.take (fromIntegral smlen) sm
  where len = S.length m

-- | Returns @True@ if the signature is valid for the given public key and
-- message.
signVerifyDetached :: PublicKey
                   -> ByteString
                   -- ^ Signature
                   -> ByteString
                   -- ^ Message
                   -> Bool
signVerifyDetached (PK k) sig sm = unsafePerformIO $
  constByteArray3 k sig sm $ \pk psig psm -> do
    res <- c_sign_verify_detached psig psm (fromIntegral len) pk
    return (res == 0)
  where len = S.length sm


foreign import ccall "crypto_sign_keypair"
  c_sign_keypair :: Ptr CChar
                 -- ^ Public key output buffer
                 -> Ptr CChar
                 -- ^ Secret key output buffer
                 -> IO CInt
                 -- ^ Always 0

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

foreign import ccall "crypto_sign"
  c_sign :: Ptr CChar
         -- ^ Signed message output buffer
         -> Ptr CULLong
         -- ^ Length of signed message
         -> Ptr CChar
         -- ^ Constant message buffer
         -> CULLong
         -- ^ Length of message input buffer
         -> Ptr CChar
         -- ^ Constant secret key buffer
         -> IO CInt
         -- ^ Always 0

foreign import ccall "crypto_sign_open"
  c_sign_open :: Ptr CChar
              -- ^ Message output buffer
              -> Ptr CULLong
              -- ^ Length of message
              -> Ptr CChar
              -- ^ Constant signed message buffer
              -> CULLong
              -- ^ Length of signed message buffer
              -> Ptr CChar
              -- ^ Public key buffer
              -> IO CInt
              -- ^ 0 if signature is verifiable, -1 otherwise

foreign import ccall "crypto_sign_detached"
    c_sign_detached :: Ptr CChar
                    -- ^ Signature output buffer
                    -> Ptr CULLong
                    -- ^ Length of the signature
                    -> Ptr CChar
                    -- ^ Constant message buffer
                    -> CULLong
                    -- ^ Length of message buffer
                    -> Ptr CChar
                    -- ^ Constant secret key buffer
                    -> IO CInt

foreign import ccall "crypto_sign_verify_detached"
    c_sign_verify_detached :: Ptr CChar
                           -- ^ Signature buffer
                           -> Ptr CChar
                           -- ^ Constant signed message buffer
                           -> CULLong
                           -- ^ Length of signed message buffer
                           -> Ptr CChar
                           -- ^ Public key buffer
                           -> IO CInt
