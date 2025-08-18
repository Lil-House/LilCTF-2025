// SPDX-License-Identifier: MIT
pragma solidity 0.8.9;
contract OysterTreasure {

    string private encryptedTreasure;
    bool private treasureUnlocked;

    constructor(string memory treasure) {
        encryptedTreasure = _xorWithOysterKey(treasure);
        treasureUnlocked = false;
    }

    function _xorWithOysterKey(string memory text) internal pure returns (string memory) {
        bytes memory textBytes = bytes(text);
        bytes memory key = bytes("shenghuo2");
        bytes memory result = new bytes(textBytes.length);

        for (uint256 i = 0; i < textBytes.length; i++) {
            result[i] = bytes1(uint8(textBytes[i]) ^ uint8(key[i % key.length]));
        }

        return string(result);
    }

    function unlockOysterTreasure(string memory attempt) public {
        require(
            keccak256(abi.encodePacked(encryptedTreasure)) ==
            keccak256(abi.encodePacked(_xorWithOysterKey(attempt))),
            "Wrong Treasure"
        );
        treasureUnlocked = true;
    }

    function isSolved() public view returns (bool) {
        return treasureUnlocked;
    }
}
