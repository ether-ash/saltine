module Crypto.Saltine.Unsafe.Box (
  SecretKey, PublicKey, Keypair, CombinedKey, Nonce, Seed,
  newKeypair, seedKeypair, derivePublicKey,
  beforeNM, newNonce,
  box, boxOpen,
  boxAfterNM, boxOpenAfterNM,
  boxSeal, boxSealOpen
  ) where

import           Crypto.Saltine.Class
import           Crypto.Saltine.Internal.Util
import qualified Crypto.Saltine.Internal.ByteSizes as Bytes
import           Crypto.Saltine.Unsafe.ScalarMult.Internal

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

-- | An opaque 'box' cryptographic secret key.
newtype SecretKey = SK ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding SecretKey where
  decode v = if B.length v == Bytes.boxSK
           then Just (SK $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (SK v) = B.convert v
  {-# INLINE encode #-}

-- | An opaque 'box' cryptographic public key.
newtype PublicKey = PK Bytes deriving (Eq, Ord)

instance IsEncoding PublicKey where
  decode v = if B.length v == Bytes.boxPK
           then Just (PK $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (PK v) = B.convert v
  {-# INLINE encode #-}

-- | A convenience type for keypairs
type Keypair = (SecretKey, PublicKey)

-- | An opaque 'boxAfterNM' cryptographic combined key.
newtype CombinedKey = CK ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding CombinedKey where
  decode v = if B.length v == Bytes.boxBeforeNM
           then Just (CK $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (CK v) = B.convert v
  {-# INLINE encode #-}

-- | An opaque 'box' nonce.
newtype Nonce = Nonce Bytes deriving (Eq, Ord)

instance IsEncoding Nonce where
  decode v = if B.length v == Bytes.boxNonce
           then Just (Nonce $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (Nonce v) = B.convert v
  {-# INLINE encode #-}

instance IsNonce Nonce where
  zero            = Nonce (B.replicate Bytes.boxNonce 0)
  nudge (Nonce n) = Nonce (nudgeBA n)

-- | An opaque 'box' seed
newtype Seed = Seed ScrubbedBytes deriving (Eq, Ord)

instance IsEncoding Seed where
  decode v = if B.length v == Bytes.boxSeed
           then Just (Seed $ B.convert v)
           else Nothing
  {-# INLINE decode #-}
  encode (Seed v) = B.convert v
  {-# INLINE encode #-}


-- | Randomly generates a secret key and a corresponding public key.
newKeypair :: IO Keypair
newKeypair = do
  -- This is a little bizarre and a likely source of errors.
  -- _err ought to always be 0.
  ((_err, sk), pk) <- buildUnsafeByteArray' Bytes.boxPK $ \pkbuf ->
    buildUnsafeByteArray' Bytes.boxSK $ \skbuf ->
      c_box_keypair pkbuf skbuf
  return (SK sk, PK pk)

-- | Randomly generates a nonce for usage with 'box' and 'boxOpen'.
newNonce :: IO Nonce
newNonce = Nonce <$> randomByteArray Bytes.boxNonce

-- | Deterministically derive a keypair from a given seed
seedKeypair :: Seed -> Keypair
seedKeypair (Seed s) = unsafePerformIO $ do
  ((_err, sk), pk) <- buildUnsafeByteArray' Bytes.boxPK $ \pkbuf ->
    buildUnsafeByteArray' Bytes.boxSK $ \skbuf ->
      constByteArray s $ \ps ->
        c_box_seed_keypair pkbuf skbuf ps
  return (SK sk, PK pk)

-- | Derive the corresponding public key from a given secret key
derivePublicKey :: SecretKey -> PublicKey
derivePublicKey (SK sk) = PK $
  snd . buildUnsafeByteArray Bytes.boxPK $ \pkbuf ->
    constByteArray sk $ \psk ->
      c_scalarmult_base pkbuf psk

-- | Build a 'CombinedKey' for sending from 'SecretKey' to
-- 'PublicKey'. This is a precomputation step which can accelerate
-- later encryption calls.
beforeNM :: SecretKey -> PublicKey -> CombinedKey
beforeNM (SK sk) (PK pk) =
  CK $ snd $ buildUnsafeByteArray Bytes.boxBeforeNM $ \ckbuf ->
    constByteArray2 pk sk $ \ppk psk ->
      c_box_beforenm ckbuf ppk psk

-- | Encrypts a message for sending to the owner of the public
-- key. They must have your public key in order to decrypt the
-- message. It is infeasible for an attacker to decrypt the message so
-- long as the 'Nonce' is not repeated.
box :: PublicKey
    -> SecretKey
    -> Nonce
    -> ByteString
    -- ^ Message
    -> ByteString
    -- ^ Ciphertext (incl. authentication tag)
box (PK pk) (SK sk) (Nonce nonce) msg =
  snd . buildUnsafeByteArray bufSize $ \pc ->
    constByteArray4 pk sk msg nonce $ \ppk psk pm pn ->
      c_box_easy pc pm (fromIntegral msgLen) pn ppk psk
  where
    bufSize = S.length msg + Bytes.boxMac
    msgLen  = S.length msg

-- | Decrypts a message sent from the owner of the public key. They
-- must have encrypted it using your public key. Returns 'Nothing' if
-- the keys and message do not match.
boxOpen :: PublicKey -> SecretKey -> Nonce
        -> ByteString
        -- ^ Ciphertext (incl. authentication tag)
        -> Maybe ByteString
        -- ^ Message
boxOpen (PK pk) (SK sk) (Nonce nonce) cipher =
  let (err, vec) = buildUnsafeByteArray bufSize $ \pm ->
        constByteArray4 pk sk cipher nonce $ \ppk psk pc pn ->
          c_box_open_easy pm pc (fromIntegral msgLen) pn ppk psk
  in hush . handleErrno err $ vec
  where
    bufSize = S.length cipher - Bytes.boxMac
    msgLen  = S.length cipher

-- | 'box' using a 'CombinedKey' and thus faster.
boxAfterNM :: CombinedKey
           -> Nonce
           -> ByteString
           -- ^ Message
           -> ByteString
           -- ^ Ciphertext (incl. authentication tag)
boxAfterNM (CK ck) (Nonce nonce) msg =
  snd . buildUnsafeByteArray bufSize $ \pc ->
    constByteArray3 ck msg nonce $ \pck pm pn ->
      c_box_easy_afternm pc pm (fromIntegral msgLen) pn pck
  where
    bufSize = S.length msg + Bytes.boxMac
    msgLen  = S.length msg

-- | 'boxOpen' using a 'CombinedKey' and is thus faster.
boxOpenAfterNM :: CombinedKey
               -> Nonce
               -> ByteString
               -- ^ Ciphertext (incl. authentication tag)
               -> Maybe ByteString
               -- ^ Message
boxOpenAfterNM (CK ck) (Nonce nonce) cipher =
  let (err, vec) = buildUnsafeByteArray bufSize $ \pm ->
        constByteArray3 ck cipher nonce $ \pck pc pn ->
          c_box_open_easy_afternm pm pc (fromIntegral msgLen) pn pck
  in hush . handleErrno err $ vec
  where
    bufSize = S.length cipher - Bytes.boxMac
    msgLen  = S.length cipher


-- | Encrypts a message for sending to the owner of the public
-- key. The message is unauthenticated, but permits integrity checking.
boxSeal :: PublicKey -> ByteString -> IO ByteString
boxSeal (PK pk) msg = fmap snd . buildUnsafeByteArray' bufSize $ \pc ->
  constByteArray2 pk msg $ \ppk pm ->
    c_box_seal pc pm (fromIntegral msgLen) ppk
  where
    bufSize = S.length msg + Bytes.sealedBox
    msgLen  = S.length msg

-- | Decrypts a sealed box message. The message must have been
-- encrypted using the receiver's public key.
-- Returns 'Nothing' if keys and message do not match or integrity
-- is violated.
boxSealOpen :: PublicKey
            -> SecretKey
            -> ByteString
            -- ^ Ciphertext
            -> Maybe ByteString
            -- ^ Message
boxSealOpen (PK pk) (SK sk) cipher =
  let (err, vec) = buildUnsafeByteArray bufSize $ \pm ->
        constByteArray3 pk sk cipher $ \ppk psk pc ->
          c_box_seal_open pm pc (fromIntegral msgLen) ppk psk
  in hush . handleErrno err $ vec
  where
    bufSize = S.length cipher - Bytes.sealedBox
    msgLen  = S.length cipher

-- | Should always return a 0.
foreign import ccall "crypto_box_keypair"
  c_box_keypair :: Ptr CChar
                -- ^ Public key
                -> Ptr CChar
                -- ^ Secret key
                -> IO CInt
                -- ^ Always 0

foreign import ccall "crypto_box_seed_keypair"
  c_box_seed_keypair :: Ptr CChar
                     -- ^ Public key output buffer
                     -> Ptr CChar
                     -- ^ Secret key output buffer
                     -> Ptr CChar
                     -- ^ Constant seed buffer
                     -> IO CInt

-- | The secretbox C API uses C strings.
foreign import ccall "crypto_box_easy"
  c_box_easy :: Ptr CChar
             -- ^ Cipher output buffer
             -> Ptr CChar
             -- ^ Constant message input buffer
             -> CULLong
             -- ^ Length of message input buffer
             -> Ptr CChar
             -- ^ Constant nonce buffer
             -> Ptr CChar
             -- ^ Constant public key buffer
             -> Ptr CChar
             -- ^ Constant secret key buffer
             -> IO CInt
             -- ^ Always 0

-- | The secretbox C API uses C strings.
foreign import ccall "crypto_box_open_easy"
  c_box_open_easy :: Ptr CChar
                  -- ^ Message output buffer
                  -> Ptr CChar
                  -- ^ Constant ciphertext input buffer
                  -> CULLong
                  -- ^ Length of message input buffer
                  -> Ptr CChar
                  -- ^ Constant nonce buffer
                  -> Ptr CChar
                  -- ^ Constant public key buffer
                  -> Ptr CChar
                  -- ^ Constant secret key buffer
                  -> IO CInt
                  -- ^ 0 for success, -1 for failure to verify

-- | Single target key precompilation.
foreign import ccall "crypto_box_beforenm"
  c_box_beforenm :: Ptr CChar
                 -- ^ Combined key output buffer
                 -> Ptr CChar
                 -- ^ Constant public key buffer
                 -> Ptr CChar
                 -- ^ Constant secret key buffer
                 -> IO CInt
                 -- ^ Always 0

-- | Precompiled key crypto box. Uses C strings.
foreign import ccall "crypto_box_easy_afternm"
  c_box_easy_afternm :: Ptr CChar
                     -- ^ Cipher output buffer
                     -> Ptr CChar
                     -- ^ Constant message input buffer
                     -> CULLong
                     -- ^ Length of message input buffer (incl. 0s)
                     -> Ptr CChar
                     -- ^ Constant nonce buffer
                     -> Ptr CChar
                     -- ^ Constant combined key buffer
                     -> IO CInt
                     -- ^ Always 0

-- | The secretbox C API uses C strings.
foreign import ccall "crypto_box_open_easy_afternm"
  c_box_open_easy_afternm :: Ptr CChar
                          -- ^ Message output buffer
                          -> Ptr CChar
                          -- ^ Constant ciphertext input buffer
                          -> CULLong
                          -- ^ Length of message input buffer (incl. 0s)
                          -> Ptr CChar
                          -- ^ Constant nonce buffer
                          -> Ptr CChar
                          -- ^ Constant combined key buffer
                          -> IO CInt
                          -- ^ 0 for success, -1 for failure to verify


-- | The sealedbox C API uses C strings.
foreign import ccall "crypto_box_seal"
  c_box_seal :: Ptr CChar
             -- ^ Cipher output buffer
             -> Ptr CChar
             -- ^ Constant message input buffer
             -> CULLong
             -- ^ Length of message input buffer
             -> Ptr CChar
             -- ^ Constant public key buffer
             -> IO CInt
             -- ^ Always 0

-- | The sealedbox C API uses C strings.
foreign import ccall "crypto_box_seal_open"
  c_box_seal_open :: Ptr CChar
                  -- ^ Message output buffer
                  -> Ptr CChar
                  -- ^ Constant ciphertext input buffer
                  -> CULLong
                  -- ^ Length of message input buffer
                  -> Ptr CChar
                  -- ^ Constant public key buffer
                  -> Ptr CChar
                  -- ^ Constant secret key buffer
                  -> IO CInt
                  -- ^ 0 for success, -1 for failure to decrypt
