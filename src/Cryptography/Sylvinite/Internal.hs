{-# LANGUAGE ScopedTypeVariables #-}

module Cryptography.Sylvinite.Internal where

import Data.Bits (shift)
import Data.Word
import Data.ByteString as BS

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
      getN maxN = fromIntegral . BS.last $ unfoldr (\a -> if 2^a > maxN then Nothing else Just (a, a+1)) 1 -- find largest 2^n less than maxN / 2, n < 63
      go (ops :: Word64) n' = 
        let maxRP = if (ops `div` 4) `div` (shift 1 n') > 0x3fffffff
                    then 0x3fffffff
                    else (ops `div` 4) `div` (shift 1 n')
         in (fromIntegral n', 8, fromIntegral $ maxRP `div` 8)
   in if opslimit < (memlimit `div` 32)
      then go opslimit (getN $ opslimit `div` 32) 
      else go opslimit (getN $ memlimit `div` 1024) 

-- this turns (opslimit, memlimit) into (n, r, p)
-- how do i turn (n, r, p) into (opslimit, memlimit)


