// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

library ECOps {
    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    uint256 constant FIELD_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    function add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory result) {
        // Input array for the precompiled ECADD contract
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;

        bool success;
        uint256[2] memory output;

        assembly {
            success := staticcall(gas(), 0x06, input, 0x80, output, 0x40)
        }

        require(success, "ECADD failed");

        result = G1Point(output[0], output[1]);
    }
}