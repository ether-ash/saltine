module ByteSizeProperties (
  testByteSizes
  ) where

import           Crypto.Saltine.Internal.ByteSizes

import           Test.Framework.Providers.QuickCheck2
import           Test.Framework

testByteSizes :: Test
testByteSizes = buildTest $
  return $ testGroup "...Internal.ByteSizes" [

    testProperty "auth              = 32" $ auth == 32,
    testProperty "authKey           = 32" $ authKey == 32,
    testProperty "boxPK             = 32" $ boxPK == 32,
    testProperty "boxSK             = 32" $ boxSK == 32,
    testProperty "boxSeed           = 32" $ boxSeed == 32,
    testProperty "boxNonce          = 24" $ boxNonce == 24,
    testProperty "boxZero           = 32" $ boxZero == 32,
    testProperty "boxBoxZero        = 16" $ boxBoxZero == 16,
    testProperty "boxMac            = 16" $ boxMac == 16,
    testProperty "boxBeforeNM       = 32" $ boxBeforeNM == 32,
    testProperty "sealedBox         = 48" $ sealedBox == 48,
    testProperty "onetime           = 16" $ onetime == 16,
    testProperty "onetimeKey        = 32" $ onetimeKey == 32,
    testProperty "mult              = 32" $ mult == 32,
    testProperty "multScalar        = 32" $ multScalar == 32,
    testProperty "secretBoxKey      = 32" $ secretBoxKey == 32,
    testProperty "secretBoxNonce    = 24" $ secretBoxNonce == 24,
    testProperty "secretBoxMac      = 16" $ secretBoxMac == 16,
    testProperty "secretBoxZero     = 32" $ secretBoxZero == 32,
    testProperty "secretBoxBoxZero  = 16" $ secretBoxBoxZero == 16,
    testProperty "aead16_..._ABYTES = 16" $ aead_xchacha20poly1305_ietf_ABYTES == 16,
    testProperty "sign              = 64" $ sign == 64,
    testProperty "signPK            = 32" $ signPK == 32,
    testProperty "signSK            = 64" $ signSK == 64,
    testProperty "signSeed          = 32" $ signSeed == 32,
    testProperty "streamKey         = 32" $ streamKey == 32,
    testProperty "streamNonce       = 24" $ streamNonce == 24,
    testProperty "hash              = 64" $ hash == 64,
    testProperty "shorthash         =  8" $ shorthash == 8,
    testProperty "shorthashKey      = 16" $ shorthashKey == 16,
    testProperty "generichashMin    = 16" $ generichashMin == 16,
    testProperty "generichashMax    = 64" $ generichashMax == 64,
    testProperty "generichash       = 32" $ generichash == 32,
    testProperty "generichashKeyMin = 16" $ generichashKeyMin == 16,
    testProperty "generichashKeyMax = 64" $ generichashKeyMax == 64,
    testProperty "generichashKey    = 32" $ generichashKey == 32

    ]
