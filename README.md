# VDF
A Solidity implementation of a VDF verifier contract, please note the code has not been audited and the preformance may not be  completly optimized.
The verrify proof function checks that given: an input random, y, pi, number of iterations and a potential prime, that (1) the hash of the input random and y matches on all digits of the potential prime except the bottom twelve bits and the top bit and that the potential prime passes a random base miller rabin test. Next it checks that pi is a valid VDF proof over the inputs.
