pragma circom 2.0.0;

// Smallest circuit with one output and one public input, for the prove/verify cross-checks against snarkjs on both curves.
template Mul() {
    signal input a;
    signal input b;
    signal output c;
    c <== a * b;
}

component main {public [b]} = Mul();
