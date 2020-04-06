pragma solidity ^0.6.4;

import './Verifier.sol';

contract VerifierTesting is Verifier {
    function big_add_external(bytes calldata a, bytes calldata b) external view returns(bytes memory) {
        return big_add(a, b);
    }

    function big_sub_external(bytes calldata a, bytes calldata b) external view returns(bytes memory) {
        return big_sub(a, b);
    }

    function verify_vdf_proof_gas(bytes32 input_random, bytes memory y, bytes memory pi, uint256 iterations, uint256 prime) public returns(bool){
        verify_vdf_proof(input_random, y, pi, iterations, prime);
        return true;
    }
}