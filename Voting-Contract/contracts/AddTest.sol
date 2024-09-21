// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./Bn128.sol";

contract AddTest {
    Bn128.G1Point public p1;
    Bn128.G1Point public p2;
    Bn128.G1Point public result;

    function addition(uint256 p1_x, uint256 p1_y, uint256 p2_x, uint256 p2_y) public {
        p1 = Bn128.G1Point(p1_x, p1_y);
        p2 = Bn128.G1Point(p2_x, p2_y);
        result = Bn128.add(p1, p2);
    }
}