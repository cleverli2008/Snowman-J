# Snowman-J
A rapid identity-based encryption (IBE), attribute-based encryption (ABE) and chameleon hash(CH) implementation tool in Java, which is based on Java Pairing Based Cryptography Library (JPBC).

* KP-HABE-NMaCS

	We use the Snowman-J to implement the key-policy hierarchical-authority ABE with non-monotonic access structures (KP-HABE-NMaCS) construction and the outsourced extension construction, along with an HABE (CP-HABEwCS, Attribute-based access control with constant-size ciphertext in cloud computing, IEEE Trans. Cloud Comput. 2017) one as a benchmark. 

	The implementation of KP-HABE-NMaCS construction includes six algorithms, i.e. Setup, AuthKeyGen, AuthDelegate, UserKeyGen, Encrypt and Decrypt. Compared with the KP-HABE-NMaCS construction, the outsourced extension one includes one more algorithm, i.e. Transform. Meanwhile, the implementation of CP-HABEwCS construction includes five algorithms, i.e. Setup, CreateDA, Delegate, Encrypt, Decrypt.

	The source codes can be found in \schemes\KP_HABE_NMaCS.java, \schemes\OKP_HABE_NMaCS.java and \schemes\CP_HABEwCS.java.
	
	The pairings we employed are the default Type A pairing and the default Type D pairing from jPBC.

* IB-CH

	+  LSXD21, Efficient identity-based chameleon hash for mobile devices
	+  XSLD20, Identity-Based Chameleon Hash without Random Oracles and Application in the Mobile Internet, ICC'2021
	+  ZSNS03, ID-Based Chameleon Hashes from Bilinear Pairings, IACR Cryptol. ePrint Arch. 2003/208 

	The implementation of each construction includes four algorithms, i.e. Setup, KeyGen, Hash, Col. The source codes can be found in \IB-CH\LSXD21.java, \IB-CH\XSLD20.java, \IB-CH\ZSNS03_One.java and \IB-CH\ZSNS03_Two.java. Besides, \IB-CH\Test_IBCH.java is the test file.

* IBEET

	+  IBEET, Identity-based encryption with outsourced equality test in cloud computing, Inf. Sci., 2016.
	+  IBEET-DBA, Identity-based encryption with equality test and datestamp-based authorization mechanism, Theor. Comput. Sci., 2021.
	+  IBEET-FTBA, Identity-Based Encryption with Equality Test and Flexible Time-Based Authorization for Cloud Computing, submitted to TDSC.

	The implementations of the above IBEET constructions all consist of six algorithms, which are Setup, KeyGen, Trapdoor (also called Auth in IBEET-DBA), Encrypt, Test, Decrypt. The corresponding source codes can be found in \IBEET-FTBA\IBEET.java, \IBEET-FTBA\IBEET-DBA.java (based on the Type A pairings), \IBEET-FTBA\IBEET_DBA_TypeD.java (based on the Type D pairings), \IBEET-FTBA\IBEET_FTBA.java (based on the Type A pairings), \IBEET-FTBA\IBEET_FTBA_TypeD.java (based on the Type D pairings). In addition, \IBEET-FTBA\Utils.java is a utility class for implementing IBEET constructions and \IBEET-FTBA\Schnorr_OTS.java is the implementation of a one-time strong signature.

