// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {BLS12381} from "./BLS12381.sol";

/// @notice On-chain verification of vASM, the ASM scheme of Boneh, Drijvers and Neven
/// (BDN) and ASMwSA/ASMwCA (same verification), for measuring gas.
///
/// Orientation: by default public keys are in G1 and hashes and signatures in G2, because
/// the EIP-2537 precompiles make G1 cheaper than G2. The schemes are unchanged by this
/// swap. vASM is also available with the keys in G2 (the orientation of the paper).
///
/// A group's public data is written once by its registrant and read on every verification.
/// The contract does not check it: as in the paper's model, the verifier has to recognise
/// a set-up group, so registration must be done or authorised by the group itself (vASM:
/// gpk signed by the members; ASMwSA/ASMwCA: key proofs checked before registering).
/// Subgroups S are given as strictly increasing 1-based indices, 2 bytes each.
contract ASMVerifier {
    // 96 bytes of a G1 point (x || y, 48 bytes each) in three storage words
    struct P96 { bytes32 a; bytes32 b; bytes32 c; }
    // a G2 point as two P96 halves (x.c0 || x.c1 and y.c0 || y.c1)
    struct P192 { P96 lo; P96 hi; }

    struct VasmGroup { address owner; uint32 n; bool keysInG2; bytes32 gid; }
    struct MspGroup { address owner; uint32 n; bytes32 apkcHi; bytes16 apkcLo; P96 apk; }

    mapping(uint256 => VasmGroup) public vasmGroups;
    mapping(uint256 => mapping(uint256 => P96)) internal vasmMpk1;     // keys in G1
    mapping(uint256 => mapping(uint256 => P192)) internal vasmMpk2;    // keys in G2
    mapping(uint256 => MspGroup) public mspGroups;
    mapping(uint256 => mapping(uint256 => P96)) internal mspPk;       // pk_j
    mapping(uint256 => mapping(uint256 => P96)) internal mspWpk;      // pk_j^{a_j}
    mapping(uint256 => mapping(uint256 => P192)) internal mspH2;      // H2(apk, j)
    // the same schemes with the keys in G2 (orientation of the paper)
    struct MspGroup2 { address owner; uint32 n; bytes32 c0; bytes32 c1; bytes32 c2; P192 apk; }
    mapping(uint256 => MspGroup2) public mspGroups2;
    mapping(uint256 => mapping(uint256 => P192)) internal mspWpk2;    // pk_j^{a_j} in G2
    mapping(uint256 => mapping(uint256 => P96)) internal mspH2g1;     // H2(apk, j) in G1

    bytes internal constant DST_VASM = "vASM-v2-H0";
    bytes internal constant DST_H0 = "MSP-ASM-v2-H0";
    bytes internal constant DST_H2 = "MSP-ASM-v2-H2";

    // -g1 and -g2 in EIP-2537 encoding
    bytes internal constant NEG_G1 =
        hex"0000000000000000000000000000000017f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb00000000000000000000000000000000114d1d6855d545a8aa7d76c8cf2e21f267816aef1db507c96655b9d5caac42364e6f38ba0ecb751bad54dcd6b939c2ca";
    bytes internal constant NEG_G2 =
        hex"00000000000000000000000000000000024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb80000000000000000000000000000000013e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e000000000000000000000000000000000d1b3cc2c7027888be51d9ef691d77bcb679afda66c73f17f9ee3837a55024f78c71363275a75d75d86bab79f74782aa0000000000000000000000000000000013fa4d4a0ad8b1ce186ed5061789213d993923066dddaf1040bc3ff59f825c78df74f2d75467e25e0f55f8a00fa030ed";

    uint8 public constant VASM = 0;
    uint8 public constant VASM_G2KEYS = 1;
    uint8 public constant BDN_HASHED = 2;
    uint8 public constant BDN_STORED = 3;
    uint8 public constant ASMWSA_HASHED = 4;
    uint8 public constant ASMWSA_STORED = 5;
    uint8 public constant BDN_G2KEYS_HASHED = 6;
    uint8 public constant BDN_G2KEYS_STORED = 7;
    uint8 public constant ASMWSA_G2KEYS_HASHED = 8;
    uint8 public constant ASMWSA_G2KEYS_STORED = 9;

    event Verified(uint8 indexed scheme, uint256 indexed group, bytes32 msgHash);

    // ------------------------------------------------------------------ registration

    function registerVasm(uint256 id, bytes32 gid, uint32 n, bool keysInG2) external {
        require(vasmGroups[id].owner == address(0) && n > 0, "taken");
        vasmGroups[id] = VasmGroup(msg.sender, n, keysInG2, gid);
    }

    /// Stores MPK_start, MPK_{start+1}, ... from consecutive EIP-2537 encodings.
    function addVasmKeys(uint256 id, uint256 start, bytes calldata keys) external {
        VasmGroup storage g = vasmGroups[id];
        require(g.owner == msg.sender, "owner");
        uint256 size = g.keysInG2 ? 256 : 128;
        require(keys.length % size == 0 && start >= 1 && start - 1 + keys.length / size <= g.n, "range");
        for (uint256 k = 0; k < keys.length / size; k++) {
            if (g.keysInG2) {
                vasmMpk2[id][start + k] = P192(_pack(keys, k * size), _pack(keys, k * size + 128));
            } else {
                vasmMpk1[id][start + k] = _pack(keys, k * size);
            }
        }
    }

    function registerMsp(uint256 id, uint32 n, bytes calldata apk, bytes calldata apkc) external {
        require(mspGroups[id].owner == address(0) && n > 0, "taken");
        require(apk.length == 128 && apkc.length == 48, "apk");
        mspGroups[id] = MspGroup(msg.sender, n, bytes32(apkc[0:32]), bytes16(apkc[32:48]), _pack(apk, 0));
    }

    /// Stores pk_j, pk_j^{a_j} (G1) and H2(apk, j) (G2) for j = start, start+1, ...
    function addMspKeys(uint256 id, uint256 start, bytes calldata pk, bytes calldata wpk, bytes calldata h2)
        external
    {
        MspGroup storage g = mspGroups[id];
        require(g.owner == msg.sender, "owner");
        uint256 cnt = pk.length / 128;
        require(pk.length == cnt * 128 && wpk.length == cnt * 128 && h2.length == cnt * 256, "len");
        require(start >= 1 && start - 1 + cnt <= g.n, "range");
        for (uint256 k = 0; k < cnt; k++) {
            mspPk[id][start + k] = _pack(pk, k * 128);
            mspWpk[id][start + k] = _pack(wpk, k * 128);
            mspH2[id][start + k] = P192(_pack(h2, k * 256), _pack(h2, k * 256 + 128));
        }
    }

    /// Keys in G2: apk (256 bytes), its compressed form (96 bytes, used in the hashes).
    function registerMsp2(uint256 id, uint32 n, bytes calldata apk, bytes calldata apkc) external {
        require(mspGroups2[id].owner == address(0) && n > 0, "taken");
        require(apk.length == 256 && apkc.length == 96, "apk");
        mspGroups2[id] = MspGroup2(msg.sender, n, bytes32(apkc[0:32]), bytes32(apkc[32:64]), bytes32(apkc[64:96]),
            P192(_pack(apk, 0), _pack(apk, 128)));
    }

    /// Keys in G2: stores pk_j^{a_j} (G2) and H2(apk, j) (G1) for j = start, start+1, ...
    function addMspKeys2(uint256 id, uint256 start, bytes calldata wpk, bytes calldata h2) external {
        MspGroup2 storage g = mspGroups2[id];
        require(g.owner == msg.sender, "owner");
        uint256 cnt = h2.length / 128;
        require(h2.length == cnt * 128 && wpk.length == cnt * 256, "len");
        require(start >= 1 && start - 1 + cnt <= g.n, "range");
        for (uint256 k = 0; k < cnt; k++) {
            mspWpk2[id][start + k] = P192(_pack(wpk, k * 256), _pack(wpk, k * 256 + 128));
            mspH2g1[id][start + k] = _pack(h2, k * 128);
        }
    }

    // ------------------------------------------------------------------ verification

    /// vASM: e(prod_{i in S} mpk_i, H0(gid, m)) = e(g1, sigma), keys in G1, sigma in G2.
    function verifyVasm(uint256 id, bytes calldata S, bytes calldata m, bytes calldata sig)
        public view returns (bool)
    {
        VasmGroup storage g = vasmGroups[id];
        require(g.n > 0 && !g.keysInG2 && sig.length == 256, "group/sig");
        bytes memory apkS = _sumG1(vasmMpk1[id], S, g.n);
        bytes memory h = BLS12381.hashToG2(_encGidMsg(g.gid, m), DST_VASM);
        return _check2(apkS, h, NEG_G1, sig);
    }

    /// vASM in the orientation of the paper: e(H0(gid, m), prod mpk_i) = e(sigma, g2).
    function verifyVasmG2Keys(uint256 id, bytes calldata S, bytes calldata m, bytes calldata sig)
        public view returns (bool)
    {
        VasmGroup storage g = vasmGroups[id];
        require(g.n > 0 && g.keysInG2 && sig.length == 128, "group/sig");
        bytes memory apkS = _sumG2(vasmMpk2[id], S, g.n);
        bytes memory h = BLS12381.hashToG1(_encGidMsg(g.gid, m), DST_VASM);
        return _check2(h, apkS, sig, NEG_G2);
    }

    /// BDN: e(pk, H0(apk, m)) e(apk, prod_{i in S} H2(apk, i)) = e(g1, s), with sigma = (s, pk).
    /// As in BDN's scheme, pk = prod_{i in S} pk_i comes with the signature (256 + 128 bytes)
    /// and is not checked against S; BDN's second pairing binds the members through apk.
    function verifyBdn(uint256 id, bytes calldata S, bytes calldata m, bytes calldata sig, bool storedH2)
        public view returns (bool)
    {
        MspGroup storage g = mspGroups[id];
        require(g.n > 0 && sig.length == 384, "group/sig");
        bytes memory h0 = BLS12381.hashToG2(_encApkMsg(g, m), DST_H0);
        bytes memory h2S = storedH2 ? _sumG2(mspH2[id], S, g.n) : _hashH2(g, S);
        return _check2(sig[256:384], h0, _unpack1(g.apk), abi.encodePacked(h2S, NEG_G1, sig[0:256]));
    }

    /// ASMwSA / ASMwCA: e(spk, H0(apk, m) prod_{j in S} H2(apk, j)) = e(g1, sigma),
    /// spk = prod_{j in S} pk_j^{a_j} computed by the verifier from the group's data.
    function verifyAsmwsa(uint256 id, bytes calldata S, bytes calldata m, bytes calldata sig, bool storedH2)
        public view returns (bool)
    {
        MspGroup storage g = mspGroups[id];
        require(g.n > 0 && sig.length == 256, "group/sig");
        bytes memory spk = _sumG1(mspWpk[id], S, g.n);
        bytes memory h = BLS12381.hashToG2(_encApkMsg(g, m), DST_H0);
        bytes memory h2S = storedH2 ? _sumG2(mspH2[id], S, g.n) : _hashH2(g, S);
        BLS12381.g2AddInPlace(h, h2S);
        return _check2(spk, h, NEG_G1, sig);
    }

    /// BDN with keys in G2: e(H0(apk, m), pk) e(prod H2(apk, i), apk) = e(s, g2), sigma = (s, pk),
    /// s in G1 (128 bytes) and pk in G2 (256 bytes) from the signature.
    function verifyBdnG2Keys(uint256 id, bytes calldata S, bytes calldata m, bytes calldata sig, bool storedH2)
        public view returns (bool)
    {
        MspGroup2 storage g = mspGroups2[id];
        require(g.n > 0 && sig.length == 384, "group/sig");
        bytes memory h0 = BLS12381.hashToG1(_encApk2Msg(g, m), DST_H0);
        bytes memory h2S = storedH2 ? _sumG1(mspH2g1[id], S, g.n) : _hashH2g1(g, S);
        return _check2(abi.encodePacked(h0, sig[128:384]), h2S, _unpack2(g.apk), abi.encodePacked(sig[0:128], NEG_G2));
    }

    /// ASMwSA / ASMwCA with keys in G2: e(H0(apk, m) prod H2(apk, j), spk) = e(sigma, g2).
    function verifyAsmwsaG2Keys(uint256 id, bytes calldata S, bytes calldata m, bytes calldata sig, bool storedH2)
        public view returns (bool)
    {
        MspGroup2 storage g = mspGroups2[id];
        require(g.n > 0 && sig.length == 128, "group/sig");
        bytes memory spk = _sumG2(mspWpk2[id], S, g.n);
        bytes memory h = BLS12381.hashToG1(_encApk2Msg(g, m), DST_H0);
        bytes memory h2S = storedH2 ? _sumG1(mspH2g1[id], S, g.n) : _hashH2g1(g, S);
        BLS12381.g1AddInPlace(h, h2S);
        return _check2(h, spk, sig, NEG_G2);
    }

    /// A transaction that verifies and logs; used to measure gas as a user would pay it.
    function submit(uint8 scheme, uint256 id, bytes calldata S, bytes calldata m, bytes calldata sig) external {
        bool ok;
        if (scheme == VASM) ok = verifyVasm(id, S, m, sig);
        else if (scheme == VASM_G2KEYS) ok = verifyVasmG2Keys(id, S, m, sig);
        else if (scheme == BDN_HASHED) ok = verifyBdn(id, S, m, sig, false);
        else if (scheme == BDN_STORED) ok = verifyBdn(id, S, m, sig, true);
        else if (scheme == ASMWSA_HASHED) ok = verifyAsmwsa(id, S, m, sig, false);
        else if (scheme == ASMWSA_STORED) ok = verifyAsmwsa(id, S, m, sig, true);
        else if (scheme == BDN_G2KEYS_HASHED) ok = verifyBdnG2Keys(id, S, m, sig, false);
        else if (scheme == BDN_G2KEYS_STORED) ok = verifyBdnG2Keys(id, S, m, sig, true);
        else if (scheme == ASMWSA_G2KEYS_HASHED) ok = verifyAsmwsaG2Keys(id, S, m, sig, false);
        else if (scheme == ASMWSA_G2KEYS_STORED) ok = verifyAsmwsaG2Keys(id, S, m, sig, true);
        require(ok, "invalid signature");
        emit Verified(scheme, id, keccak256(m));
    }

    /// RFC 9380 check of the hash-to-G2 code (test only).
    function hashToG2(bytes calldata m, bytes calldata dst) external view returns (bytes memory) {
        return BLS12381.hashToG2(m, dst);
    }

    // ------------------------------------------------------------------ internals

    function _encGidMsg(bytes32 gid, bytes calldata m) internal pure returns (bytes memory) {
        return abi.encodePacked(uint32(32), gid, uint32(m.length), m);
    }

    function _check2(bytes memory a, bytes memory b, bytes memory c, bytes memory d) internal view returns (bool) {
        return BLS12381.pairingCheck(abi.encodePacked(a, b, c, d));
    }

    function _encApkMsg(MspGroup storage g, bytes calldata m) internal view returns (bytes memory) {
        return abi.encodePacked(uint32(48), g.apkcHi, g.apkcLo, uint32(m.length), m);
    }

    /// prod_{j in S} H2(apk, j), hashing each value (enc(apk, j) as in groups.enc).
    function _hashH2(MspGroup storage g, bytes calldata S) internal view returns (bytes memory acc) {
        uint256 l = _checkS(S, g.n);
        for (uint256 k = 0; k < l; k++) {
            uint256 j = uint16(bytes2(S[2 * k:2 * k + 2]));
            bytes memory h = BLS12381.hashToG2(
                abi.encodePacked(uint32(48), g.apkcHi, g.apkcLo, uint32(48), bytes16(0), j), DST_H2);
            if (k == 0) acc = h;
            else BLS12381.g2AddInPlace(acc, h);
        }
    }

    function _encApk2Msg(MspGroup2 storage g, bytes calldata m) internal view returns (bytes memory) {
        return abi.encodePacked(uint32(96), g.c0, g.c1, g.c2, uint32(m.length), m);
    }

    function _hashH2g1(MspGroup2 storage g, bytes calldata S) internal view returns (bytes memory acc) {
        uint256 l = _checkS(S, g.n);
        for (uint256 k = 0; k < l; k++) {
            uint256 j = uint16(bytes2(S[2 * k:2 * k + 2]));
            bytes memory h = BLS12381.hashToG1(
                abi.encodePacked(uint32(96), g.c0, g.c1, g.c2, uint32(48), bytes16(0), j), DST_H2);
            if (k == 0) acc = h;
            else BLS12381.g1AddInPlace(acc, h);
        }
    }

    function _unpack2(P192 storage p) internal view returns (bytes memory out) {
        out = new bytes(256);
        uint256 dst;
        assembly ("memory-safe") { dst := add(out, 32) }
        _unpackTo(dst, p.lo.a, p.lo.b, p.lo.c);
        _unpackTo(dst + 128, p.hi.a, p.hi.b, p.hi.c);
    }

    function _checkS(bytes calldata S, uint256 n) internal pure returns (uint256 l) {
        l = S.length / 2;
        require(l > 0 && S.length % 2 == 0, "S");
        uint256 prev = 0;
        for (uint256 k = 0; k < l; k++) {
            uint256 i = uint16(bytes2(S[2 * k:2 * k + 2]));
            require(i > prev && i <= n, "S order");
            prev = i;
        }
    }

    function _sumG1(mapping(uint256 => P96) storage pts, bytes calldata S, uint256 n)
        internal view returns (bytes memory acc)
    {
        uint256 l = _checkS(S, n);
        acc = new bytes(256);                       // acc || next
        for (uint256 k = 0; k < l; k++) {
            P96 storage p = pts[uint16(bytes2(S[2 * k:2 * k + 2]))];
            (bytes32 a, bytes32 b, bytes32 c) = (p.a, p.b, p.c);
            uint256 dst;
            assembly ("memory-safe") { dst := add(add(acc, 32), mul(gt(k, 0), 128)) }
            _unpackTo(dst, a, b, c);
            if (k > 0) {
                assembly ("memory-safe") {
                    if iszero(staticcall(gas(), 0x0b, add(acc, 32), 256, add(acc, 32), 128)) { revert(0, 0) }
                }
            }
        }
        assembly ("memory-safe") { mstore(acc, 128) }
    }

    function _sumG2(mapping(uint256 => P192) storage pts, bytes calldata S, uint256 n)
        internal view returns (bytes memory acc)
    {
        uint256 l = _checkS(S, n);
        acc = new bytes(512);
        for (uint256 k = 0; k < l; k++) {
            P192 storage p = pts[uint16(bytes2(S[2 * k:2 * k + 2]))];
            uint256 dst;
            assembly ("memory-safe") { dst := add(add(acc, 32), mul(gt(k, 0), 256)) }
            _unpackTo(dst, p.lo.a, p.lo.b, p.lo.c);
            _unpackTo(dst + 128, p.hi.a, p.hi.b, p.hi.c);
            if (k > 0) {
                assembly ("memory-safe") {
                    if iszero(staticcall(gas(), 0x0d, add(acc, 32), 512, add(acc, 32), 256)) { revert(0, 0) }
                }
            }
        }
        assembly ("memory-safe") { mstore(acc, 256) }
    }

    /// Packs the 128-byte encoding at e[off:off+128] (two padded 48-byte values) into 3 words.
    function _pack(bytes calldata e, uint256 off) internal pure returns (P96 memory p) {
        require(e.length >= off + 128, "pack");
        bytes32 a; bytes32 b; bytes32 c; uint256 pad;
        assembly ("memory-safe") {
            let q := add(e.offset, off)
            pad := or(shr(128, calldataload(q)), shr(128, calldataload(add(q, 64))))
            a := calldataload(add(q, 16))
            b := or(and(calldataload(add(q, 48)), not(0xffffffffffffffffffffffffffffffff)),
                    shr(128, calldataload(add(q, 80))))
            c := calldataload(add(q, 96))
        }
        require(pad == 0, "padding");
        p = P96(a, b, c);
    }

    /// Writes the 128-byte encoding of a packed value to memory at dst.
    function _unpackTo(uint256 dst, bytes32 a, bytes32 b, bytes32 c) internal pure {
        assembly ("memory-safe") {
            mstore(dst, 0)
            mstore(add(dst, 16), a)
            mstore(add(dst, 48), b)
            mstore(add(dst, 64), 0)
            mstore(add(dst, 80), shl(128, b))
            mstore(add(dst, 96), c)
        }
    }

    function _unpack1(P96 storage p) internal view returns (bytes memory out) {
        out = new bytes(128);
        uint256 dst;
        assembly ("memory-safe") { dst := add(out, 32) }
        _unpackTo(dst, p.a, p.b, p.c);
    }
}
