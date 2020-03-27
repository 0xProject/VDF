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


library LibLimb {

    using LibLimb for *;

    struct Branch {
        uint256[] limbs;
    }

    function add(
        Branch memory a,
        Branch memory b
    )
        internal
        pure
        returns (Branch memory c)
    {
        uint256 carry = 0;
        uint256 numLimbs = max(a.limbs.length, b.limbs.length);
        c.limbs = new uint256[](numLimbs);
        for (uint i = 0; i < numLimbs; i++) {
            uint256 limbA = a.limbs.get(i);
            uint256 limbB = b.limbs.get(i);
            c.limbs[i] = limbA + limbB + carry;
            carry = shouldAdditionCarry(limbA, limbB, carry);
        }
        if (carry > 0) {
            append(c, carry);
        }
    }

    function sub(
        Branch memory a,
        Branch memory b
    )
        internal
        pure
        returns (Branch memory c)
    {
        uint256 carry = 0;
        for (uint i = 0; i < max(a.limbs.length, b.limbs.length); i++) {
            uint256 limbA = a.limbs.get(i);
            uint256 limbB = b.limbs.get(i);
            c.limbs[i] = limbA - limbB - carry;
            carry = shouldSubtractionCarry(limbA, limbB, carry);
        }
        if (carry > 0) {
            append(c, uint256(-1));
        }
    }

    // NOTE(jalextowle): This function is not memory-safe in general. In the context,
    // of this program, append is safely used (we are always appending to the last
    // memory array that was allocated), but it is not safe to use in general. This is
    // why the function has been marked as `private`.
    function append(
        Branch memory branch,
        uint256 lastLimb
    )
        private
        pure
    {
        assembly {
            let branch_ptr := mload(mload(branch))
            let branch_size := mload(branch_ptr)

            // Solidity points empty arrays to `0x60`, which is not a safe location
            // to write to. We must allocate new memory for the branch.
            if eq(branch_ptr, 0x60) {
                branch_ptr := mload(0x40)
            }

            let new_size := add(branch_size, 0x20)
            mstore(branch_ptr, new_size)
            // HACK(jalextowle): This is the correct storage slot, but this is a little
            // misleading because new size is just the old size plus the length of the
            // storage slot. It's cheap though :)
            mstore(add(branch_ptr, new_size), lastLimb)

            // Update the free-memory pointer.
            mstore(0x40, add(branch_ptr, add(new_size, 0x20)))
        }
    }

    function get(
        uint256[] memory array,
        uint256 idx
    )
        internal
        pure
        returns (uint256)
    {
        return idx < array.length ? array[idx] : 0;
    }

    function max(
        uint256 a,
        uint256 b
    )
        private
        pure
        returns (uint256)
    {
        return a > b ? a : b;
    }

    function shouldAdditionCarry(
        uint256 a,
        uint256 b,
        uint256 c
    )
        private
        pure
        returns (uint256)
    {
        return a + b + c < a ? 1 : 0;
    }

    function shouldSubtractionCarry(
        uint256 a,
        uint256 b,
        uint256 c
    )
        private
        pure
        returns (uint256)
    {
        return a - b - c > a ? 1 : 0;
    }
}
