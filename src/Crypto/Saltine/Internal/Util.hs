module Crypto.Saltine.Internal.Util where

import           Foreign.C
import           Foreign.Marshal.Alloc    (mallocBytes)
import           Foreign.Ptr
import           System.IO.Unsafe

import           Control.Applicative
import qualified Data.ByteArray         as B
import           Data.ByteArray           (ByteArrayAccess, ByteArray, Bytes, ScrubbedBytes)
import qualified Data.ByteString        as S
import           Data.ByteString          (ByteString)
import           Data.ByteString.Unsafe
import           Data.Monoid

-- | @snd . cycleSucc@ computes the 'succ' of a 'Bounded', 'Eq' 'Enum'
-- with wraparound. The @fst . cycleSuc@ is whether the wraparound
-- occurred (i.e. @fst . cycleSucc == (== maxBound)@).
cycleSucc :: (Bounded a, Enum a, Eq a) => a -> (Bool, a)
cycleSucc a = (top, if top then minBound else succ a)
  where top = a == maxBound

-- | Treats a 'ByteString' as a little endian bitstring and increments
-- it.
nudgeBS :: ByteString -> ByteString
nudgeBS i = fst $ S.unfoldrN (S.length i) go (True, i) where
  go (toSucc, bs) = do
    (hd, tl)      <- S.uncons bs
    let (top, hd') = cycleSucc hd

    if   toSucc
    then return (hd', (top, tl))
    else return (hd, (top && toSucc, tl))

-- | Computes the orbit of a endomorphism... in a very brute force
-- manner. Exists just for the below property.
--
-- prop> length . orbit nudgeBS . S.pack . replicate 0 == (256^)
orbit :: Eq a => (a -> a) -> a -> [a]
orbit f a0 = orbit' (f a0) where
  orbit' a = if a == a0 then [a0] else a : orbit' (f a)

-- | 0-pad a 'ByteString'
pad :: Int -> ByteString -> ByteString
pad n = mappend (S.replicate n 0)

-- | Remove a 0-padding from a 'ByteString'
unpad :: Int -> ByteString -> ByteString
unpad = S.drop

-- | Converts a C-convention errno to an Either
handleErrno :: CInt -> (a -> Either String a)
handleErrno err a = case err of
  0  -> Right a
  -1 -> Left "failed"
  n  -> Left ("unexpected error code: " ++ show n)

unsafeDidSucceed :: IO CInt -> Bool
unsafeDidSucceed = go . unsafePerformIO
  where go 0 = True
        go _ = False

-- | Convenience function for accessing constant C strings
constByteStrings :: [ByteString] -> ([CStringLen] -> IO b) -> IO b
constByteStrings =
  foldr (\v kk -> \k -> (unsafeUseAsCStringLen v) (\a -> kk (\as -> k (a:as)))) ($ [])

-- | Slightly safer cousin to 'buildUnsafeByteString' that remains in the
-- 'IO' monad.
buildUnsafeByteString' :: Int -> (Ptr CChar -> IO b) -> IO (b, ByteString)
buildUnsafeByteString' n k = do
  ph  <- mallocBytes n
  bs  <- unsafePackMallocCStringLen (ph, fromIntegral n)
  out <- unsafeUseAsCString bs k
  return (out, bs)

-- | Extremely unsafe function, use with utmost care! Builds a new
-- ByteString using a ccall which is given access to the raw underlying
-- pointer. Overwrites are UNCHECKED and 'unsafePerformIO' is used so
-- it's difficult to predict the timing of the 'ByteString' creation.
buildUnsafeByteString :: Int -> (Ptr CChar -> IO b) -> (b, ByteString)
buildUnsafeByteString n = unsafePerformIO . buildUnsafeByteString' n

-- | Build a sized random 'ByteString' using Sodium's bindings to
-- @/dev/urandom@.
randomByteString :: Int -> IO ByteString
randomByteString n =
  snd <$> buildUnsafeByteString' n (`c_randombytes_buf` fromIntegral n)

-- | To prevent a dependency on package 'errors'
hush :: Either s a -> Maybe a
hush = either (const Nothing) Just

type BaPtr = Ptr CChar

-- TODO: ScrubbedBytes for keys
randomByteArray :: ByteArray a => Int -> IO a
randomByteArray n =
  snd <$> buildUnsafeByteArray' n (`c_randombytes_buf` fromIntegral n)

buildUnsafeByteArray' :: ByteArray a => Int -> (Ptr CChar -> IO b) -> IO (b, a)
buildUnsafeByteArray' n k = B.allocRet n k

buildUnsafeByteArray :: ByteArray a => Int -> (Ptr CChar -> IO b) -> (b, a)
buildUnsafeByteArray n = unsafePerformIO . buildUnsafeByteArray' n

constByteArray :: ByteArrayAccess a => a -> (Ptr CChar -> IO b) -> IO b
constByteArray = B.withByteArray

constByteArray2 :: (ByteArrayAccess a, ByteArrayAccess b)
                => a -> b
                -> (BaPtr -> BaPtr -> IO e)
                -> IO e
constByteArray2 a b k =
  B.withByteArray a $ \pa ->
  B.withByteArray b $ \pb ->
  k pa pb

constByteArray3 :: (ByteArrayAccess a, ByteArrayAccess b, ByteArrayAccess c)
                => a -> b -> c
                -> (BaPtr -> BaPtr -> BaPtr -> IO e)
                -> IO e
constByteArray3 a b c k =
  B.withByteArray a $ \pa ->
  B.withByteArray b $ \pb ->
  B.withByteArray c $ \pc ->
  k pa pb pc

constByteArray4 :: (ByteArrayAccess a, ByteArrayAccess b, ByteArrayAccess c, ByteArrayAccess d)
                => a -> b -> c -> d
                -> (BaPtr -> BaPtr -> BaPtr -> BaPtr -> IO e)
                -> IO e
constByteArray4 a b c d k =
  B.withByteArray a $ \pa ->
  B.withByteArray b $ \pb ->
  B.withByteArray c $ \pc ->
  B.withByteArray d $ \pd ->
  k pa pb pc pd


constByteArray5 :: (ByteArrayAccess a, ByteArrayAccess b, ByteArrayAccess c, ByteArrayAccess d, ByteArrayAccess e)
                => a -> b -> c -> d -> e
                -> (BaPtr -> BaPtr -> BaPtr -> BaPtr -> BaPtr -> IO x)
                -> IO x
constByteArray5 a b c d e k =
  B.withByteArray a $ \pa ->
  B.withByteArray b $ \pb ->
  B.withByteArray c $ \pc ->
  B.withByteArray d $ \pd ->
  B.withByteArray e $ \pe ->
  k pa pb pc pd pe


-- | Treats a 'ByteArray' as a little endian bitstring and increments
-- it.
nudgeBA :: (ByteArrayAccess a, ByteArray b)
        => a -> b
nudgeBA = B.convert . nudgeBS . B.convert


foreign import ccall "randombytes_buf"
  c_randombytes_buf :: Ptr CChar -> CInt -> IO ()
