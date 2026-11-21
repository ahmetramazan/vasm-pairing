// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice BLS12-381 helpers on top of the EIP-2537 precompiles (Prague and later).
/// Points use the EIP-2537 encoding: a field element is 64 bytes (16 zero bytes and
/// 48 bytes big-endian), a G1 point is x || y (128 bytes), a G2 point is
/// x.c0 || x.c1 || y.c0 || y.c1 (256 bytes).
library BLS12381 {
    // base field prime p, split into its first 32 and last 16 bytes
    uint256 internal constant P_HI = 0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f624;
    uint256 internal constant P_LO = 0x1eabfffeb153ffffb9feffffffffaaab;

    /// RFC 9380, Section 5.3.1, with SHA-256. lenInBytes is a multiple of 32, at most 256.
    function expandMsgXmd(bytes memory msg_, bytes memory dst, uint256 lenInBytes)
        internal pure returns (bytes memory out)
    {
        require(dst.length <= 255 && lenInBytes % 32 == 0 && lenInBytes <= 256, "xmd");
        bytes memory dstPrime = abi.encodePacked(dst, uint8(dst.length));
        bytes32 b0 = sha256(abi.encodePacked(bytes32(0), bytes32(0), msg_, uint16(lenInBytes), uint8(0), dstPrime));
        bytes32 bi = sha256(abi.encodePacked(b0, uint8(1), dstPrime));
        out = new bytes(lenInBytes);
        assembly ("memory-safe") { mstore(add(out, 32), bi) }
        for (uint256 i = 2; i <= lenInBytes / 32; i++) {
            bi = sha256(abi.encodePacked(b0 ^ bi, uint8(i), dstPrime));
            assembly ("memory-safe") { mstore(add(out, mul(i, 32)), bi) }
        }
    }

    /// Reduces `count` 64-byte blocks of `uniform` modulo p with the MODEXP precompile
    /// (base^1 mod p) and returns them as EIP-2537 field elements.
    function toField(bytes memory uniform, uint256 count) internal view returns (bytes memory fe) {
        fe = new bytes(count * 64);
        assembly ("memory-safe") {
            let buf := mload(0x40)
            mstore(buf, 64)              // length of base
            mstore(add(buf, 32), 1)      // length of exponent
            mstore(add(buf, 64), 48)     // length of modulus
            for { let k := 0 } lt(k, count) { k := add(k, 1) } {
                let src := add(add(uniform, 32), mul(k, 64))
                mstore(add(buf, 96), mload(src))
                mstore(add(buf, 128), mload(add(src, 32)))
                mstore8(add(buf, 160), 1)
                mstore(add(buf, 161), P_HI)
                mstore(add(buf, 193), shl(128, P_LO))
                if iszero(staticcall(gas(), 0x05, buf, 209, add(add(fe, 48), mul(k, 64)), 48)) { revert(0, 0) }
            }
        }
    }

    /// RFC 9380 hash_to_curve, suite BLS12381G2_XMD:SHA-256_SSWU_RO_ (with the caller's DST).
    /// MAP_FP2_TO_G2 clears the cofactor, and clearing is linear, so map(u0) + map(u1) is the
    /// RFC result.
    function hashToG2(bytes memory msg_, bytes memory dst) internal view returns (bytes memory h) {
        bytes memory fe = toField(expandMsgXmd(msg_, dst, 256), 4);
        h = new bytes(256);
        bytes memory q = new bytes(512);
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x11, add(fe, 32), 128, add(q, 32), 256)) { revert(0, 0) }
            if iszero(staticcall(gas(), 0x11, add(fe, 160), 128, add(q, 288), 256)) { revert(0, 0) }
            if iszero(staticcall(gas(), 0x0d, add(q, 32), 512, add(h, 32), 256)) { revert(0, 0) }
        }
    }

    /// RFC 9380 hash_to_curve, suite BLS12381G1_XMD:SHA-256_SSWU_RO_ (with the caller's DST).
    function hashToG1(bytes memory msg_, bytes memory dst) internal view returns (bytes memory h) {
        bytes memory fe = toField(expandMsgXmd(msg_, dst, 128), 2);
        h = new bytes(128);
        bytes memory q = new bytes(256);
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x10, add(fe, 32), 64, add(q, 32), 128)) { revert(0, 0) }
            if iszero(staticcall(gas(), 0x10, add(fe, 96), 64, add(q, 160), 128)) { revert(0, 0) }
            if iszero(staticcall(gas(), 0x0b, add(q, 32), 256, add(h, 32), 128)) { revert(0, 0) }
        }
    }

    /// a := a + b in G2 (both 256-byte encodings).
    function g2AddInPlace(bytes memory a, bytes memory b) internal view {
        bytes memory buf = abi.encodePacked(a, b);
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x0d, add(buf, 32), 512, add(a, 32), 256)) { revert(0, 0) }
        }
    }

    /// a := a + b in G1 (both 128-byte encodings).
    function g1AddInPlace(bytes memory a, bytes memory b) internal view {
        bytes memory buf = abi.encodePacked(a, b);
        assembly ("memory-safe") {
            if iszero(staticcall(gas(), 0x0b, add(buf, 32), 256, add(a, 32), 128)) { revert(0, 0) }
        }
    }

    /// True iff the product of the pairings of the (G1, G2) pairs in `input` is 1.
    /// Points that are not on the curve or not in the subgroup make the precompile fail,
    /// and the result is false.
    function pairingCheck(bytes memory input) internal view returns (bool ok) {
        assembly ("memory-safe") {
            let out := mload(0x40)
            let success := staticcall(gas(), 0x0f, add(input, 32), mload(input), out, 32)
            ok := and(success, eq(mload(out), 1))
        }
    }
}
