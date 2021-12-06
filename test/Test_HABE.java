package test;

import java.util.Map;
import java.util.Scanner;

import abe.Attribute;
import abe.Threshold;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.PairingManager;
import schemes.CP_HABEwCS;
import schemes.KP_HABE_NMaCS;
import schemes.OKP_HABE_NMaCS;

/**
 * @ClassName: Test_HABE
 * @Description: Test the algorithms of different HABE schemes
 * @author:cleverli2008
 * @date:2021/11/26
 */

public class Test_HABE {

	private Pairing pairing = PairingManager.getDefaultPairing();

	public Element testCP_HABEwCS(Attribute[] universe, Attribute[] attributes, String message) {

		CP_HABEwCS scheme = new CP_HABEwCS();

		// Run the setup algorithm
		Map<String, Object>[] res = scheme.setup(universe);
		Map<String, Object> pk = res[0];
		Map<String, Object> msk = res[1];

		// Run the createDA algorithm
		Map<String, Object> sk_da = scheme.createDA(msk, pk, attributes);

		// Run the delegation algorithm
		Map<String, Object> sk_da_u = scheme.delegate(pk, sk_da, attributes);

		// Set the threshold
		Threshold threshold = new Threshold(attributes, attributes.length);

		// Run the encryption algorithm
		Map<String, Object> ct = scheme.encrypt(pk, message, threshold);

		// Run the decryption algorithm
		Element m = scheme.decrypt(threshold, pk, sk_da_u, ct);

//		System.out.println(m);
		return m;

	}

	public Element testKP_HABE_NMaCS(int q, String[] id_vector, Attribute[] attributes, String policy, String message,
			String id) {

		KP_HABE_NMaCS scheme = new KP_HABE_NMaCS();

		// Run the setup algorithm
		Map[] keys = scheme.setup(q);
		Map pk = keys[0];
		Map msk = keys[1];

		// Run the authority key generation algorithm
		Map ak = scheme.authkeygen(pk, msk, id_vector);

		// Run the authority key delegation algorithm
		Map ak_new = scheme.authdelegate(pk, ak, id);

		// Run the user key generation algorithm
		Map sk = scheme.userkeygen(pk, ak, policy);

		// Run the encryption algorithm
		Map ct = scheme.encrypt(pk, id_vector, attributes, message);

		// Run the decryption algorithm
		Element m = scheme.decrypt(pk, ct, sk);

//		System.out.println(m);
		return m;
	}

	public Element testOKP_HABE_NMaCS(int q, String[] id_vector, Attribute[] attributes, String policy, String message,
			String id) {

		OKP_HABE_NMaCS scheme = new OKP_HABE_NMaCS();

		// Run the setup algorithm
		Map[] keys = scheme.setup(q);
		Map pk = keys[0];
		Map msk = keys[1];

		// Run the authority key generation algorithm
		Map ak = scheme.authkeygen(pk, msk, id_vector);

		// Run the authority key delegation algorithm
		Map ak_new = scheme.authdelegate(pk, ak, id);

		// Run the user key generation algorithm
		Map[] key = scheme.userkeygen(pk, ak, policy);
		Map sk = key[0];
		Map dk = key[1];

		// Run the encryption algorithm
		Map ct = scheme.encrypt(pk, id_vector, attributes, message);

		// Run the transformation algorithm
		Map it = scheme.transform(pk, ct, sk);

		// Run the decryption algorithm
		Element m = scheme.decrypt(it, dk);

//		System.out.println(m);
		return m;
	}

	public static void main(String[] args) throws Exception {

		System.out.println("Please input the name of IB-CH scheme:");
		Scanner sc = new Scanner(System.in);
		String schemeName = sc.next();
		Test_HABE test = new Test_HABE();

		// Init parameters
		int q = 12;
		int u_number = 10;
		int str_number = 2;
		int id_number = 1;

		int policy_size = str_number;

		int negated_attr_number = 0;
//		int negated_attr_number = policy_size; 

		// Init the attribute universe
		Attribute[] universe = new Attribute[u_number];
		for (int i = 0; i < universe.length; i++) {
			universe[i] = new Attribute("attr_name" + i, "attr_val" + i);
		}

		// Init the attribute set
		Attribute[] attributes = new Attribute[str_number];
		for (int i = 0; i < attributes.length; i++) {
			attributes[i] = new Attribute("attr_name" + i, "attr_val" + i);
		}

		// Init the policy
		String policy = null;
		for (int i = 0; i < policy_size - negated_attr_number; i++) {
			if (i == 0) {
				policy = "attr_name" + i + ":attr_val" + i;
			} else {
				policy = policy + " and attr_name" + i + ":attr_val" + i;
			}
		}

		for (int i = 0; i < negated_attr_number; i++) {
			if (policy == null && i == 0) {
				policy = "attr_name" + i + ":-attr_val_n" + i;
			} else {
				policy = policy + " and attr_name" + i + ":-attr_val_n" + i;
			}
		}

		// Init the identity vector
		String[] id_vector = new String[id_number];
		for (int i = 0; i < id_vector.length; i++) {
			id_vector[i] = "I_" + i;
		}

		// Init the message
		String message = "This a test!";

		String id = "I_x";

		// Call the test algorithms
		if (schemeName.equals("CP_HABEwCS"))
			test.testCP_HABEwCS(universe, attributes, message);
		else if (schemeName.equals("KP_HABE_NMaCS"))
			test.testKP_HABE_NMaCS(q, id_vector, attributes, policy, message, id);
		else if (schemeName.equals("OKP_HABE_NMaCS"))
			test.testOKP_HABE_NMaCS(q, id_vector, attributes, policy, message, id);
		else
			System.out.print("Valid Scheme!");

	}
}
