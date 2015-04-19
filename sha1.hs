{- sha1.hs -- SHA1 secure hash
 -
 - Copyright (C) 2015, Antoine Catton <devel at antoine dot catton dot fr>
 -
 - This software may be modified and distributed under the terms
 - of the MIT license.  See the LICENSE file for details.
 -}

import Data.List (length, repeat, take, drop, map, foldl1, foldl, reverse, zipWith4)
import Data.List.Split (chunksOf)
import Data.Bits
import Data.Word (Word8, Word32)

-- TODO: Delete me
import Data.ByteString (getContents, unpack)
import Text.Printf (printf)

-- TODO: Move that outside this module?
-- FIXME: Is there a builtin function for this?
bignumToWords8 :: Int -> Int -> [Word8]
bignumToWords8 base n =
    let go 0 = []
        go n =
            let r = n `mod` base
                n' = n `div` base
            in r:(go n')
    in map toWord8 $ reverse $ go n
        where toWord8 = fromIntegral :: Int -> Word8

-- TODO: Move that outside this module?
-- FIXME: Is there a builtin function for this
words8ToBignum :: Int -> [Word8] -> Int
words8ToBignum base l = foldl1 go $ map toInt l where
    go acc i = (acc * base) + i
    toInt = fromIntegral :: Word8 -> Int

-- TODO: Move that outside this module?
-- FIXME: Is there a builtin function for this?
words8ToWords32 :: [Word8] -> [Word32]
words8ToWords32 l = map go $ chunksOf 4 l where
    toWord32 = fromIntegral :: Int -> Word32
    go = toWord32 . words8ToBignum 256

-- TODO: Move that outside this module?
-- FIXME: Is there a builtin function for this?
words32ToWords8 :: [Word32] -> [Word8]
words32ToWords8 l = concat $ map go l where
    toBignum = fromIntegral :: Word32 -> Int
    go = bignumToWords8 256 . toBignum

-- TODO: Move that outside this module?
-- FIXME: Is there a builtin function for this?
fixSize :: Int -> [Word8] -> [Word8]
fixSize n l =
    let len = length l in
    if len == n then
        l
    else if len > n then
        drop (len - n) l
    else
        let padding = take (n - len) $ repeat 0 in
        padding ++ l

-- TODO: Move that outside this module?
-- FIXME: Is there a builtin function for this?
pad :: [Word8] -> [Word8]
pad l =
    let padZeros l =
            let toPad = (64 - len + 56) `mod` 64
                    where len = length l
                padding = take toPad $ repeat 0
            in l ++ padding
        concatSize len l = l ++ size
            where size = fixSize 8 $ bignumToWords8 256 len
    in concatSize len $ padZeros $ l ++ [0x80]
        where len = 8 * length l

hash :: [Word32] -> [Word8]
hash l =
    let f t b c d = -- f function defined in the RFC 3174 section 5
            if 0 <= t && t < 20 then
                (b .&. c) .|. ((complement b) .&. d)
            else if t < 40 then
                b `xor` c `xor` d
            else if t < 60 then
                (b .&. c) .|. (b .&. d) .|. (c .&. d)
            else if t < 80 then
                b `xor` c `xor` d
            else
                error "t out of boundaries" -- This should never happen

        k t = -- k function defined in the RFC 3174 section 5
            if 0 <= t && t < 20 then 0x5A827999
            else if t < 40 then 0x6ED9EBA1
            else if t < 60 then 0x8F1BBCDC
            else if t < 80 then 0xCA62C1D6
            else error "t out of boundaries" -- This should never happen

        -- Initial state defined in the RFC 3174 section 6.1
        init = (0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0)

        -- Expand the word block as explained in the RFC 3174, section 6.1, step b
        expand l =
            let l' =
                    let a = drop 13 l'
                        b = drop 8 l'
                        c = drop 2 l'
                        d = l'
                    in l ++ (map shift $ zipWith4 xor4 a b c d)
                        where shift i = rotateL i 1
                              xor4 a b c d = a `xor` b `xor` c `xor` d
            in take 80 l'

        -- Function to process a word as explained in the RFC 3174, section 6.1, step d
        processWord (a, b, c, d, e) (t, w) =
            let a' = (rotateL a 5) + (f t b c d) + e + w + (k t)
                e' = d
                d' = c
                c' = rotateL b 30
                b' = a
            in (a', b', c', d', e')

        -- Function to process a word block as explained in the RFC 3174, section 6.1
        processBlock init@(a, b, c, d, e) l =
            let (a', b', c', d', e') = foldl processWord init l in
            (a + a', b + b', c + c', d + d', e + e')
        count = zip [0..]

        -- Process the whole message (use the Method 1 from the RFC 3174)
        (a, b, c, d, e) = foldl processBlock init $ map count $ map expand $ chunksOf 16 l
        -- Convert the 5 word buffer to a byte message
        in words32ToWords8 [a, b, c, d, e]

sha1 :: [Word8] -> [Word8]
sha1 l = hash $ words8ToWords32 $ pad l

-- XXX: I have no idea what I'm doing here. I just want to print the hexadecimal
-- digest of the input.
main = do
    content <- Data.ByteString.getContents
    let digest = sha1 $ unpack content
        hexdigest = map (printf "%02x") $ digest
    foldl1 (>>) hexdigest
    putChar '\n'
