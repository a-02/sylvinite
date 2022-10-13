{-# LANGUAGE ScopedTypeVariables #-}

module Cryptography.Sylvinite.Internal where

import Cryptography.Sodium.Bindings.Scrypt
import Data.Bits (popCount)
import Data.Word
import Data.ByteString as BS
import Foreign.C.Types
import Foreign.Marshal.Array
import GHC.Prim
import System.IO.Unsafe

-- | These are identical to `cryptonite`'s scrypt parameters for easy
-- replacement. 
-- 
-- "n" is denoted "CPU/Memory cost ratio" by `cryptonite` and "Rounds to hash"
-- by `password`. This has to be a power of 2 greater than 1, so whatever 
-- creates these parameters will most likely take an n of your choosing, and 
-- then use 2^n as the value.
--
-- "r" is "Block Size"
-- "p" is "Parallelism"
-- It is required that r * p < 2^30.
-- 
-- outputLength is "Output Length". This is measured in bytes, not characters.
data Parameters = Parameters
  { n            :: Int
  , r            :: Int
  , p            :: Int
  , outputLength :: Int
  }

-- | In the version of this function present in `cryptonite`, there were
-- 3 typeclasses present in the arguments and return type. These have been
-- eliminated to their most common usage.`

{-
generate :: Parameters -> ByteString -> ByteString -> ByteString
generate parameters password salt
  | r parameters * p parameters >= 0x40000000 =
      error "Scrypt: Invalid parameters, r * p exceeds 2^30."
  | popCount (n parameters) /= 1 =
      error "Scrypt: Invalid parameters, n is not a power of 2."
  | otherwise = unsafePerformIO $ do
      let (outlen :: CULLong)    = toEnum (outputLength parameters)
          (passwdlen :: CChar)   = toEnum (BS.length password)
          (password' :: [CChar]) = (toEnum . fromEnum) <$> (BS.unpack password)
          (salt' :: [CUChar])    = coerce <$> (BS.unpack salt)
          opslimit = coerce cryptoPWHashScryptSalsa2018SHA256OpsLimitInteractive
          memlimit = cryptoPWHashScryptSalsa2018SHA256MemLimitInteractive
      out <- mallocArray (outputLength parameters)
      passwd <- newArray password'
      salt_ <- newArray salt' 
      _ <- cryptoPWHashScryptSalsa2018SHA256
             out
             outlen 
             passwd
             passwdlen
             salt_
             opslimit
             memlimit
      result <- peekArray (outputLength parameters) out
      let result' = BS.pack $ coerce <$> result
      return result'
-}
