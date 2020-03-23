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

pragma solidity ^0.5.16;


contract Verifier {
    // Preset 2048 bit mod
    bytes constant MODULUS = "0xC7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5";
    
    // Version of VDF verification which uses more calldata
    function verify_vdf_proof(bytes32 input_random, bytes memory y, bytes memory pi, uint256 iterations, uint256 prime) public view {
        check_hash_to_prime(input_random, y, prime);
        
        uint r = expmod(2, iterations, prime);
        bytes memory part_1 = bignum_expmod(pi, r, MODULUS);
        bytes memory part_2 = bignum_expmod(uint_to_big_num(input_random), r, MODULUS);
        
        require(big_cmp(big_mulmod(part_1, part_2, MODULUS), y), "VDF proof verification failed");
    }
    
    // Casts a bytes32 value into bytes memory string, could be made better with msb and better packing
    // Might be critical to reduce the cost of the expmod precompile
    // TODO - @Alex please double check my work I haven't done as much assembly fuckery lately 🙏
    function uint_to_big_num(bytes32 data) internal pure returns(bytes memory) {
        bytes memory ptr;
        
        assembly {
            ptr := mload(0x40)
            mstore(ptr, 32)
            mstore(add(ptr, 32), data)
        }
        return ptr;
    }
    
    function big_mulmod(bytes memory a, bytes memory b, bytes memory mod) internal pure returns(bytes memory c) {
        // TODO - big number mulmod
    }
    
    // Cheap big number comparsion using hash
    // TODO - Verify that this is actually cheaper for the bitsize in question
    function big_cmp(bytes memory a, bytes memory b) internal pure returns(bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
    
    // Thanks to Dankrad Feist for the bignum exp, hash to prime, and prime test.
    // https://github.com/dankrad/rsa-bounty/blob/master/contract/rsa_bounty.sol
    
    uint constant prime_mask = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_f000;
        
    // This function checks if:
    // (1) If h = Hash(input_random, y)
    //    (1a) That h is equal to prime except at the 12 last bits and the most signifigant bit.
    //    (1b) that the prime has msb 1
    // (2) That prime canidate passes the miller rabbin test with 28 round of randomly derived bases [derived from n]
    // TODO - consider adding blockhash to the random base derivation for extra security.
    function check_hash_to_prime(bytes32 input_random, bytes memory y, uint256 prime) public view {
        // Check p is correct result for hash-to-prime
        require(prime & prime_mask == uint(sha256(abi.encodePacked(input_random, y))) & prime_mask);
        require(prime > (1 << 255));
        require(miller_rabin_test(prime));
    }
    
    // Expmod for small operands
    function expmod(uint base, uint e, uint m) public view returns (uint o) {
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
    function bignum_expmod(bytes memory base, uint e, bytes memory m) public view returns (bytes memory o) {
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

    uint constant miller_rabin_checks = 28;

    // Use the Miller-Rabin test to check whether n>3, odd is a prime
    function miller_rabin_test(uint n) public view returns (bool) {
        require(n > 3);
        require(n & 0x1 == 1);
        uint d = n - 1;
        uint r = 0;
        while(d & 0x1 == 0) {
            d /= 2;
            r += 1;
        }
        for(uint i = 0; i < miller_rabin_checks; i++) {
            // pick a random integer a in the range [2, n − 2]
            uint a = (uint256(sha256(abi.encodePacked(n, i))) % (n - 3)) + 2;
            uint x = expmod(a, d, n);
            if(x == 1 || x == n - 1) {
                continue;
            }
            bool check_passed = false;
            for(uint j = 1; j < r; j++) {
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
