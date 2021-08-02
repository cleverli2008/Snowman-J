# Snowman-J
A rapid ABE implementation tool in Java, which is based on Java Pairing Based Cryptography Library (JPBC).

* KP-HABE-NMaCS

	We use the Snowman-J to implement the key-policy hierarchical-authority ABE with non-monotonic access structures (KP-HABE-NMaCS) construction and the outsourced extension construction, along with an HABE (CP-HABEwCS, Attribute-based access control with constant-size ciphertext in cloud computing, IEEE Trans. Cloud Comput. 2017) one as a benchmark. 

	The implementation of KP-HABE-NMaCS construction includes six algorithms, i.e. Setup, AuthKeyGen, AuthDelegate, UserKeyGen, Encrypt and Decrypt. Compared with the KP-HABE-NMaCS construction, the outsourced extension one includes one more algorithm, i.e. Transform. Meanwhile, the implementation of CP-HABEwCS construction includes five algorithms, i.e. Setup, CreateDA, Delegate, Encrypt, Decrypt.

	The source code can be found in \schemes\KP_HABE_NMaCS.java, \schemes\OKP_HABE_NMaCS.java and \schemes\CP_HABEwCS.java.


