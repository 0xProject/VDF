/*

  Copyright 2020 ZeroEx Intl.

  Licensed under the Apache License, Version 2.0 (the "License");
  you may not use this file except in compliance with the License.
  You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.

*/

pragma solidity ^0.5.11;


contract Verifier {
    // Preset 2048 bit mod
    bytes constant MODULUS = "0xC7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5";
    bytes constant HALF_MOD = "0x63CB86776E61D83AA248100D3D5309E6B9C88840E3C87AF8D43937A31AA85DADBFF86DC70F508C4F6397C9E8B28008DEB90D775661566F19502083F832461409D18FAD85BBB2FFC5A25A5B7FE499C25B237584E3E7AF42C96A07519E4001CF9ADA78A5025A8FBDFEBC0DF268B398B25D475CC8E1626B985DDF1AFAC95EF7A9257BF46D77E936337E01623CD7C4EB269B9FA21384A1CEF33675CAAF9F51BEA8ACFB09AC04FC299A5AE58C09D6EE406682B04F8856354AD6B2C396484A92DED6995E394AC9321490792630EE2D9E1DBC91F2B58B526CE9B9EC390F9251FE078D9898FAAB0A8B94335E66187CA82A64127399D2F5B40BFBDE0B1CCEA4631B0E63F2";

    // Version of VDF verification which uses more calldata
    function verify_vdf_proof(bytes32 input_random, bytes memory y, bytes memory pi, uint256 iterations, uint256 prime) public view {
        // Check that y is a group member
        require(group_member(y), "Y inproperly formated");
        require(group_member(pi), "Pi inproperly formated");
        check_hash_to_prime(input_random, y, prime);
        
        // No need to cast this into the group because the size will always be small.
        uint256 r = expmod(2, iterations, prime);

        bytes memory part_1 = bignum_expmod(pi, r, MODULUS);
        bytes memory part_2 = bignum_expmod(bytes_to_big_num(input_random), r, MODULUS);
        bytes memory proposed_y = big_mulmod(part_1, part_2, MODULUS);
        group_cast(proposed_y);
        
        require(big_cmp(proposed_y, y), "VDF proof verification failed");
    }

    // This is a writeup of the second method, but given the fairly low calldata costs we don't really need it

    // // This is the second possible method to verify the vdf, it takes less input data
    // function verify_vdf_proof2(bytes32 input_random, bytes memory pi, uint256 iterations, uint256 prime) public view { 
    //     require(group_member(pi), "Pi inproperly formated");
    //     // We don't cast r to group because it's less than 256 bits and half mod is always much larger
    //     uint256 r = expmod(2, iterations, prime);

    //     bytes memory part_1 = bignum_expmod(pi, r, MODULUS);
    //     bytes memory part_2 = bignum_expmod(bytes_to_big_num(input_random), r, MODULUS);
    //     bytes memory y = group_cast(big_mulmod(part_1, part_2, MODULUS));
        
    //     check_hash_to_prime(input_random, y, prime);
    // }

    // This function hard casts a number which must be less than MODULUS into a RSA group member
    function group_cast(bytes memory canidate)  internal pure {
        if (!group_member(canidate)) {
            big_inplace_sub(canidate, HALF_MOD);
        }
    }

    // Returns true if the group member is less than half the RSA group mod
    // NOTE - Will trim leading zeros from the canidate
    function group_member(bytes memory canidate) internal pure returns(bool) {
        // Removes any leading zeros so we can can make choices based on length
        trim(canidate);

        if (canidate.length < HALF_MOD.length) {
            return true;
        }
        if (canidate.length > HALF_MOD.length) {
            return false;
        }

        for (uint i = 0; i < canidate.length; i++) {
            // If the current byte is less than half mod's byte then the candiate is less than mod
            if (canidate[i] < HALF_MOD[i]) {
                return true;
            }
            // If it's strictly more then half mod is greater
            if (canidate[i] > HALF_MOD[i]) {
                return false;
            }
        }
        // We hit this condition if canidate == HALF_MOD
        return true;
    }

    // This trim function removes leading zeros don't contain information in our big endian format.
    function trim(bytes memory data) internal pure {
        uint256 msb = 0;
        while (data[msb] == 0) {
            msb ++;

            if (msb == data.length) {
                data = "0x";
                return;
            }
        }

        if (msb > 0) {
            // We don't want to copy data around, so we do the following assembly manipulation:
            // Move the data pointer forward by msb, then store in the length slot (current length - msb)
            assembly {
                let current_len := mload(data)
                data := add(data, msb)
                mstore(data, sub(current_len, msb))
            }
        }
    }
    
    // Casts a bytes32 value into bytes memory string
    function bytes_to_big_num(bytes32 data) internal pure returns(bytes memory ptr) {

        assembly {
            ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), data)
            // Pesimestic update to free memory pointer
            mstore(0x40, add(mload(0x40), 0x20))
        }

        // Removes any zeros which aren't needed
        trim(ptr);
    }
    
    function big_mulmod(bytes memory a, bytes memory b, bytes memory mod) internal pure returns(bytes memory c) {
        // TODO - big number mulmod
    }

    // This function writes a - b to the memory pointer at a;
    function big_inplace_sub(bytes memory a, bytes memory b) internal pure {
        // TODO - Big number sub
    }
    
    // Cheap big number comparsion using hash
    // TODO - Verify that this is actually cheaper for the bitsize in question
    function big_cmp(bytes memory a, bytes memory b) internal pure returns(bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
    
    // Thanks to Dankrad Feist for the bignum exp, hash to prime, and prime test.
    // https://github.com/dankrad/rsa-bounty/blob/master/contract/rsa_bounty.sol
    
    uint256 constant prime_mask = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_f000;
        
    // This function checks if:
    // (1) If h = Hash(input_random, y)
    //    (1a) That h is equal to prime except at the 12 last bits and the most signifigant bit.
    //    (1b) that the prime has msb 1
    // (2) That prime canidate passes the miller rabbin test with 28 round of randomly derived bases [derived from y]
    // TODO - consider adding blockhash to the random base derivation for extra security.
    function check_hash_to_prime(bytes32 input_random, bytes memory y, uint256 prime) public view {
        // Check p is correct result for hash-to-prime
        require(prime & prime_mask == uint(sha256(abi.encodePacked(input_random, y))) & prime_mask);
        require(prime > (1 << 255));
        require(miller_rabin_test(prime));
    }
    
    // Expmod for small operands
    function expmod(uint256 base, uint256 e, uint256 m) public view returns (uint o) {
        assembly {
            // Get free memory pointer
            let p := mload(0x40)
            // Store parameters for the Expmod (0x05) precompile
            mstore(p, 0x20)             // Length of Base
            mstore(add(p, 0x20), 0x20)  // Length of Exponent
            mstore(add(p, 0x40), 0x20)  // Length of Modulus
            mstore(add(p, 0x60), base)  // Base
            mstore(add(p, 0x80), e)     // Exponent
            mstore(add(p, 0xa0), m)     // Modulus

            // Call 0x05 (EXPMOD) precompile
            if iszero(staticcall(sub(gas(), 2000), 0x05, p, 0xc0, p, 0x20)) {
                revert(0, 0)
            }
            o := mload(p)
        }
    }
    
    // Expmod for bignum operands (encoded as bytes, only base and modulus)
    function bignum_expmod(bytes memory base, uint256 e, bytes memory m) public view returns (bytes memory o) {
        assembly {
            // Get free memory pointer
            let p := mload(0x40)

            // Get base length in bytes
            let bl := mload(base)
            // Get modulus length in bytes
            let ml := mload(m)

            // Store parameters for the Expmod (0x05) precompile
            mstore(p, bl)               // Length of Base
            mstore(add(p, 0x20), 0x20)  // Length of Exponent
            mstore(add(p, 0x40), ml)    // Length of Modulus
            // Use Identity (0x04) precompile to memcpy the base
            if iszero(staticcall(10000, 0x04, add(base, 0x20), bl, add(p, 0x60), bl)) {
                revert(0, 0)
            }
            mstore(add(p, add(0x60, bl)), e) // Exponent
            // Use Identity (0x04) precompile to memcpy the modulus
            if iszero(staticcall(10000, 0x04, add(m, 0x20), ml, add(add(p, 0x80), bl), ml)) {
                revert(0, 0)
            }
            
            // Call 0x05 (EXPMOD) precompile
            if iszero(staticcall(sub(gas(), 2000), 0x05, p, add(add(0x80, bl), ml), add(p, 0x20), ml)) {
                revert(0, 0)
            }

            // Update free memory pointer
            mstore(0x40, add(add(p, ml), 0x20))

            // Store correct bytelength at p. This means that with the output
            // of the Expmod precompile (which is stored as p + 0x20)
            // there is now a bytes array at location p
            mstore(p, ml)

            // Return p
            o := p
        }
    }

    uint256 constant miller_rabin_checks = 28;

    // Use the Miller-Rabin test to check whether n>3, odd is a prime
    function miller_rabin_test(uint256 n) public view returns (bool) {
        require(n > 3);
        require(n & 0x1 == 1);
        uint256 d = n - 1;
        uint256 r = 0;
        while(d & 0x1 == 0) {
            d /= 2;
            r += 1;
        }
        for(uint256 i = 0; i < miller_rabin_checks; i++) {
            // pick a random integer a in the range [2, n − 2]
            uint256 a = (uint256(sha256(abi.encodePacked(n, i))) % (n - 3)) + 2;
            uint256 x = expmod(a, d, n);
            if(x == 1 || x == n - 1) {
                continue;
            }
            bool check_passed = false;
            for(uint256 j = 1; j < r; j++) {
                x = mulmod(x, x, n);
                if(x == n - 1) {
                    check_passed = true;
                    break;
                }
            }
            if(!check_passed) {
                return false;
            }
        }
        return true;
    }
}
