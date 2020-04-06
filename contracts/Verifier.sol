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

pragma solidity ^0.6.4;

contract Verifier {
    // Preset 2048 bit mod
    bytes constant MODULUS = hex"C7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5";
    bytes constant HALF_MOD = hex"63CB86776E61D83AA248100D3D5309E6B9C88840E3C87AF8D43937A31AA85DADBFF86DC70F508C4F6397C9E8B28008DEB90D775661566F19502083F832461409D18FAD85BBB2FFC5A25A5B7FE499C25B237584E3E7AF42C96A07519E4001CF9ADA78A5025A8FBDFEBC0DF268B398B25D475CC8E1626B985DDF1AFAC95EF7A9257BF46D77E936337E01623CD7C4EB269B9FA21384A1CEF33675CAAF9F51BEA8ACFB09AC04FC299A5AE58C09D6EE406682B04F8856354AD6B2C396484A92DED6995E394AC9321490792630EE2D9E1DBC91F2B58B526CE9B9EC390F9251FE078D9898FAAB0A8B94335E66187CA82A64127399D2F5B40BFBDE0B1CCEA4631B0E63F2";

    // Version of VDF verification which uses more calldata
    function verify_vdf_proof(bytes32 input_random, bytes memory y, bytes memory pi, uint256 iterations, uint256 prime) public view {
        // Check that y is a group member
        require(group_member(y), "Y improperly formatted");
        require(group_member(pi), "Pi improperly formatted");
        check_hash_to_prime(input_random, y, prime);
        
        // No need to cast this into the group because the size will always be small.
        uint256 r = expmod(2, iterations, prime);

        bytes memory part_1 = bignum_expmod(pi, prime, MODULUS);
        part_1 = trim(part_1);
        bytes memory part_2 = bignum_expmod(bytes_to_big_num(input_random), r, MODULUS);
        part_2 = trim(part_2);
        // Gives us four times what we want
        bytes memory proposed_y = almost_mulmod(part_1, part_2, MODULUS);
        proposed_y = trim(proposed_y);
        // So we compare to four times the y
        bytes memory almost_y = almost_mulmod(y, hex"01", MODULUS);
        almost_y = trim(almost_y);
        
        require(big_eq(proposed_y, almost_y), "VDF proof verification failed");
    }

    // This function hard casts a number which must be less than MODULUS into a RSA group member
    function group_cast(bytes memory candidate)  internal view {
        if (!group_member(candidate)) {
            candidate = big_sub(candidate, HALF_MOD);
        }
    }

    // Returns true if the group member is less than half the RSA group mod
    // NOTE - Will trim leading zeros from the candidate
    function group_member(bytes memory candidate) internal pure returns(bool) {
        candidate = trim(candidate);
        return lte(candidate, HALF_MOD);
    }

    // This trim function removes leading zeros don't contain information in our big endian format.
    function trim(bytes memory data) internal pure returns(bytes memory) {
        uint256 msb = 0;
        while (data[msb] == 0) {
            msb ++;
            if (msb == data.length) {
                return hex"";
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
        return data;
    }
    
    // Casts a bytes32 value into bytes memory string
    function bytes_to_big_num(bytes32 data) internal pure returns(bytes memory ptr) {

        assembly {
            ptr := mload(0x40)
            mstore(ptr, 0x20)
            mstore(add(ptr, 0x20), data)
            // Pesimestic update to free memory pointer
            mstore(0x40, add(mload(0x40), 0x40))
        }

        // Removes any zeros which aren't needed
        ptr = trim(ptr);
    }

    // This function returns (4ab) % mod for big numbs
    function almost_mulmod(bytes memory a, bytes memory b, bytes memory mod) internal view returns(bytes memory c) {
        bytes memory part1 = bignum_expmod(modular_add(a, b), 2, mod);
        bytes memory part2 = bignum_expmod(modular_sub(a, b), 2, mod);
        // Returns (a+b)^2 - (a-b)^2 = 4ab
        return modular_sub(part1, part2);
    }

    // Uses the mod const in the contract and assumes that a < Mod, b < Mod
    // Ie that the inputs are already modular group memembers.
    function modular_add(bytes memory a, bytes memory b) internal view returns (bytes memory) {
        bytes memory result = big_add(a, b);
        if (lte(result, MODULUS) && !big_eq(result, MODULUS)) {
            return result;
        } else {
            // NOTE a + b where a < MOD, b < MOD => a+b < 2 MOD => a+b % mod = a+b - MOD
            return big_sub(result, MODULUS);
        }
    }

    function modular_sub(bytes memory a, bytes memory b) internal view returns(bytes memory) {
        if (lte(b, a)) {
            return big_sub(a, b);
        } else {
            return (big_sub(MODULUS, big_sub(b, a)));
        }
    }

    // Returns (a <= b);
    // Requires trimmed inputs
    function lte(bytes memory a, bytes memory b) internal pure returns (bool) {
        if (a.length < b.length) {
            return true;
        }
        if (a.length > b.length) {
            return false;
        }

        for (uint i = 0; i < a.length; i++) {
            // If the current byte of a is less than that of b then a is less than b
            if (a[i] < b[i]) {
                return true;
            }
            // If it's strictly more then b is greater
            if (a[i] > b[i]) {
                return false;
            }
        }
        // We hit this condition if a == b
        return true;
    }

    uint mask = 0x00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;
    // This big add function has performance on the order of the limb version, but
    // it worse because it chunks out limbs for as long as it can from the bytes and
    // when there isn't enough data for a 31 bit limb in either a or b it goes byte by byte
    // Preformance degrades to byte by byte when adding a full 2048 bit number to a small number.
    // It is best when adding two full sized 2048 bit numbers
    function big_add(bytes memory a, bytes memory b) internal view returns(bytes memory) {
        // a + b < 2*max(a, b) so this can't have more bytes than the max length + 1
        bytes memory c = new bytes(max(a.length, b.length) + 1);
        // The index from the back of the data arrays [since this is Big endian]
        uint current_index = 0;
        uint8 carry = 0;
        // This loop grabs large numbers from the byte array for as long as we can
        while (a.length - current_index > 31 && b.length - current_index > 31) {
            // Will have 31 bytes of a's next digits
            uint a_data;
            // Will have 31 bytes of b's next digits
            uint b_data;
            assembly {
                //Load from memory at the data location of a + a.length - (current_index - 32)
                // This can load a bit of extra data which will be masked off.
                a_data := mload(add(add(a, 0x20), sub(mload(a), add(current_index, 32))))
                //Load from memory at the data location of b + b.length - (current_index - 32)
                b_data := mload(add(add(b, 0x20), sub(mload(b), add(current_index, 32))))
            }
            a_data = a_data & mask;
            b_data = b_data & mask;
            // Add the input data and the carried data.
            // TODO - Limb overflow checks the implementation may break on a+b > 2^31*8 with carry != 0
            uint sum =  a_data + b_data + carry;
            // Coerce solidity into giving me the first byte as a small number;
            carry = uint8(bytes1(bytes32(sum)));
            // Slice off the carry
            sum = sum & mask;
            // Store the sum-ed digits
            assembly {
                mstore(add(add(c, 0x20), sub(mload(c), add(current_index, 32))), sum)
            }
            current_index += 31;
        }
        
        // Now we go byte by byte
        while (current_index < max(a.length, b.length)) {
            uint16 a_data;
            if (current_index < a.length) {
                a_data = uint16(uint8(a[a.length - current_index-1]));
            } else {
                a_data = 0;
            }
            
            uint16 b_data;
            if (current_index < b.length) {
                b_data = uint16(uint8(b[b.length - current_index-1]));
            } else {
                b_data = 0;
            }

            uint16 sum = a_data + b_data + carry;
            c[c.length - current_index-1] = bytes1(uint8(sum));
            carry = uint8(sum >> 8);
            current_index++;
        }
        c[0] = bytes1(carry);
        c = trim(c);
        return c;
    }

    function max(uint a, uint b) internal pure returns (uint) {
        return a > b ? a : b;
    }

    // This extra digit allows us to preform the subtraction without underflow
    uint max_set_digit = 0x0100000000000000000000000000000000000000000000000000000000000000;

    // This function reverts on underflows, and expects trimed data
    function big_sub(bytes memory a, bytes memory b) internal view returns(bytes memory) {
        require(a.length >= b.length, "Subtraction underflow");
        // a - b =< a so this can't have more bytes than a
        bytes memory c = new bytes(a.length);
        // The index from the back of the data arrays [since this is Big endian]
        uint current_index = 0;
        uint8 carry = 0;
        // This loop grabs large numbers from the byte array for as long as we can
        while (a.length - current_index > 31 && b.length - current_index > 31) {
            // Will have 31 bytes of a's next digits
            uint a_data;
            // Will have 31 bytes of b's next digits
            uint b_data;
            assembly {
                //Load from memory at the data location of a + a.length - (current_index - 32)
                // This can load a bit of extra data which will be masked off.
                a_data := mload(add(add(a, 0x20), sub(mload(a), add(current_index, 32))))
                //Load from memory at the data location of b + b.length - (current_index - 32)
                b_data := mload(add(add(b, 0x20), sub(mload(b), add(current_index, 32))))
            }
            a_data = a_data & mask;
            b_data = b_data & mask;
            uint sub_digit;
            // We now check if we can sub b_data + carry from a_data
            if (a_data >= b_data + carry) {
                sub_digit = a_data - (b_data + carry);
                carry = 0;
            } else {
                // If not we add a one digit at the top of a, then sub
                sub_digit = (a_data + max_set_digit) - (b_data + carry);
                carry = 1;
            }

            // Store the sum-ed digits
            assembly {
                mstore(add(add(c, 0x20), sub(mload(c), add(current_index, 32))), sub_digit)
            }
            current_index += 31;
        }
        
        // Now we go byte by byte through the bytes of a
        while (current_index < a.length) {
            uint16 a_data = uint16(uint8(a[a.length - current_index-1]));
            
            // Since tighly packed this may implicly be zero without being set
            uint16 b_data;
            if (current_index < b.length) {
                b_data = uint16(uint8(b[b.length - current_index-1]));
            } else {
                b_data = 0;
            }

            uint sub_digit;
            // We now check if we can sub b_data + carry from a_data
            if (a_data >= b_data + carry) {
                sub_digit = a_data - (b_data + carry);
                carry = 0;
            } else {
                // If not we add a one digit at the top of a, then sub
                sub_digit = (a_data + 0x0100) - (b_data + carry);
                carry = 1;
            }

            c[c.length - current_index-1] = bytes1(uint8(sub_digit));
            current_index++;
        }
        require(carry == 0, "Underflow error");
        c = trim(c);
        return c;
    }
    
    // Cheap big number comparsion using hash
    // TODO - Verify that this is actually cheaper for the bitsize in question
    function big_eq(bytes memory a, bytes memory b) internal pure returns(bool) {
        return keccak256(abi.encodePacked(a)) == keccak256(abi.encodePacked(b));
    }
    
    // Thanks to Dankrad Feist for the bignum exp, hash to prime, and prime test.
    // https://github.com/dankrad/rsa-bounty/blob/master/contract/rsa_bounty.sol
    
    uint256 constant prime_mask = 0x7fff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff_f000;
        
    // This function checks if:
    // (1) If h = Hash(input_random, y)
    //    (1a) That h is equal to prime except at the 12 last bits and the most signifigant bit.
    //    (1b) that the prime has msb 1
    // (2) That prime candidate passes the miller rabbin test with 28 round of randomly derived bases [derived from y]
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
            // pick a pseudo-random integer a in the range [2, n − 2]
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
