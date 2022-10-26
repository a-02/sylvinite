{-# LANGUAGE ScopedTypeVariables #-}

module Cryptography.Sylvinite.Internal where

import Cryptography.Sodium.Bindings.Scrypt
import Data.Bits (shift)
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
  } deriving (Eq, Show)

pickparams ::
  Word64 -> -- opslimit CULLong
  Word64 -> -- memlimit CSize
  (Word32, Word32, Word32)
pickparams opslimit' memlimit =
  let opslimit = if opslimit' < 32768 then 32768 else opslimit'
      getN maxN = last $ unfoldr (\n -> if 2^n > maxN then Nothing else Just (n, n+1))  -- find largest 2^n less than maxN / 2, n < 63
      go opslimit n = 
        let maxRP = if (opslimit / 4) / (shift 1 n) > 0x3fffffff
                    then 0x3fffffff
                    else (opslimit / 4) / (shift 1 n)
         in (n, 8, maxRP / 8)
   in if opslimit < (memlimit / 32)
      then go opslimit (getN $ opslimit / 32) 
      else go opslimit (getN $ memlimit / 1024) 

-- this turns (opslimit, memlimit) into (n, r, p)
-- how do i turn (n, r, p) into (opslimit, memlimit)


