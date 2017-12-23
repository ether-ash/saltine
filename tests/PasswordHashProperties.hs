{-# LANGUAGE OverloadedStrings #-}

module PasswordHashProperties (
  testPasswordHash
  ) where

import Util

import Crypto.Saltine.Core.PasswordHash

import Test.Framework.Providers.QuickCheck2
import Test.Framework

testPasswordHash :: Test
testPasswordHash = buildTest $
  return $ testGroup "...Internal.PasswordHash" [

    testProperty "Hash password and verify"
      $ \(Message pass)-> pwHashStrVerify pass
                          $ pwHashStr pass moderatePolicy]
