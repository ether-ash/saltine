{-# LANGUAGE OverloadedStrings #-}

module Main where

import SecretBoxProperties   (testSecretBox)
import AEADProperties        (testAEAD)
import BoxProperties         (testBox)
import SealedBoxProperties   (testSealedBox)
import StreamProperties      (testStream)
import AuthProperties        (testAuth)
import OneTimeAuthProperties (testOneTimeAuth)
import SignProperties        (testSign)
import ScalarMultProperties  (testScalarMult)
import HashProperties        (testHash)
import ByteSizeProperties    (testByteSizes)
import UnsafeAEADProperties  (testUnsafeAEAD)
import Crypto.Saltine

import Test.Framework

runOpts :: RunnerOptions
runOpts = mempty { ropt_color_mode   = Just ColorAlways
                 , ropt_test_options = Just testOpts
                 }

testOpts :: TestOptions
testOpts = mempty { topt_maximum_generated_tests = Just 20000 }

main :: IO ()
main = do
  sodiumInit
  flip defaultMainWithOpts runOpts [
        testBox,
        testSealedBox,
        testSecretBox,
        testAEAD,
        testUnsafeAEAD,
        testStream,
        testAuth,
        testOneTimeAuth,
        testSign,
        testScalarMult,
        testHash,
        testByteSizes
        ]
