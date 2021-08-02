# Snowman-J
A rapid ABE implementation tool in Java

* KP-HABE-NMaCS

We use the Snowman-J, which is based on Java Pairing Based Cryptography Library (JPBC), to implement the key-policy hierarchical-authority ABE with non-monotonic access structures (KP-HABE-NMaCS) scheme and the outsourced extension scheme along with an attribute-based access control with constant-size ciphertext (CP-HABEwCS, Attribute-based access control with constant-size ciphertext in cloud computing, IEEE Trans. Cloud Comput. 2017) one as the benchmark. 

The implementation of KP-HABE-NMaCS scheme includes six algorithms, i.e. Setup, AuthKeyGen, AuthDelegate, UserKeyGen, Encrypt and Decrypt. Compared with KP-HABE-NMaCS, the outsourced extension scheme includes one more algorithm, i.e Transform. Meanwhile, the implementation that of CP-HABEwCS includes five algorithms, i.e. Setup, CreateDA, Delegate, Encrypt, Decrypt.

The source code can be found in \schemes\KP_HABE_NMaCS.java, \schemes\OKP_HABE_NMaCS.java and \schemes\CP_HABEwCS.java.
