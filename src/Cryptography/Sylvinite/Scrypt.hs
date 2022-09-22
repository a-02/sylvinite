module Cryptography.Sylvinite.Scrypt where

import Data.Word
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
  { n            :: Word64
  , r            :: Int
  , p            :: Int
  , outputLength :: Int
  }

-- | In the version of this function present in `cryptonite`, there were
-- 3 typeclasses present in the arguments and return type. These have been
-- eliminated to their most common usage.`
generate :: Parameters -> ByteString -> ByteString -> ByteString
generate parameters password salt = undefined
