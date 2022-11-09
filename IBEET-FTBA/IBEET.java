package IBEET;


import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import utils.Hash;

/**
 * Created by cleverli on 2022.9.19
 **/

public class IBEET {

	private Pairing pairing = PairingFactory.getPairing("scheme/a.properties");

	public List<Map<String, Object>> setup() {

		long startTime = System.nanoTime();

		// Pick hash functions
		Hash H_1 = new Hash("SHA-256");
		Hash H_2 = new Hash("SHA-1");
		Hash H_3 = new Hash("SHA-1");

		// Generate the master key
		Element s = pairing.getZr().newRandomElement().getImmutable();
		Element s_prime = pairing.getZr().newRandomElement().getImmutable();

		Map<String, Object> masterKey = new HashMap<String, Object>();
		masterKey.put("type", "msk");
		masterKey.put("s", s);
		masterKey.put("s_prime", s_prime);

		// Generate public parameters
		Element g = pairing.getG1().newRandomElement().getImmutable();

		Element g_1 = g.powZn(s_prime).getImmutable();
		Element g_2 = g.powZn(s).getImmutable();

		Map<String, Object> publicKey = new HashMap<String, Object>();
		publicKey.put("type", "pk");
		publicKey.put("g", g);
		publicKey.put("g_1", g_1);
		publicKey.put("g_2", g_2);
		publicKey.put("H_1", H_1);
		publicKey.put("H_2", H_2);
		publicKey.put("H_3", H_3);

		// Set the key array
		List<Map<String, Object>> res = new ArrayList<Map<String, Object>>();
		res.add(0, publicKey);
		res.add(1, masterKey);

		// Evaluate
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return res;
	}

	public Map<String, Object> keyGen(Map<String, Object> pk, Map<String, Object> msk, String ID) {

		long startTime = System.nanoTime();

		if (pk == null || !(((String) pk.get("type")).equals("pk"))) {
			System.out.println("The input pk is error!");
			return null;
		}

		if (msk == null || !(((String) msk.get("type")).equals("msk"))) {
			System.out.println("The input msk is error!");
			return null;
		}

		if (ID == null || ID.trim().length() == 0) {
			System.out.println("The input ID is error!");
			return null;
		}

		Element s = ((Element) msk.get("s")).duplicate().getImmutable();
		Element s_prime = ((Element) msk.get("s_prime")).duplicate().getImmutable();
		Hash H_1 = ((Hash) pk.get("H_1"));

		// Use H_1 to hash ID
		byte[] byte_H_1_ID = H_1.hash(ID.getBytes());
		Element h_ID = Utils.bytes2element(byte_H_1_ID, "G1").getImmutable();

		// Compute F_2(ID) and F_3(ID)
		Element K_1 = h_ID.powZn(s_prime).getImmutable();
		Element K_2 = h_ID.powZn(s).getImmutable();

		// Set the secret key
		Map<String, Object> sk = new HashMap<String, Object>();
		sk.put("type", "sk");
		sk.put("ID", ID);
		sk.put("K_1", K_1);
		sk.put("K_2", K_2);

		// Evaluate
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return sk;
	}

	public Map<String, Object> trapdoor(Map<String, Object> sk) {

		long startTime = System.nanoTime();

		if (sk == null || !(((String) sk.get("type")).equals("sk"))) {
			System.out.println("The input sk is error!");
			return null;
		}

		Element K_1 = ((Element) sk.get("K_1")).duplicate().getImmutable();
		String ID = (String) sk.get("ID");

		// Set the trapdoor
		Map<String, Object> td = new HashMap<String, Object>();
		td.put("type", "td");
		td.put("ID", ID);
		td.put("D_1", K_1);

		// Evaluate
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return td;
	}

	public Map<String, Object> encrypt(Map<String, Object> pk, String ID, byte[] m) {

		long startTime = System.nanoTime();

		if (pk == null || !(((String) pk.get("type")).equals("pk"))) {
			System.out.println("The input pk is error!");
			return null;
		}

		if (ID == null || ID.trim().length() == 0) {
			System.out.println("The input ID is error!");
			return null;
		}

		if (m == null || m.length == 0) {
			System.out.println("The input message is error!");
			return null;
		}

		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();
		Hash H_1 = ((Hash) pk.get("H_1"));
		Hash H_2 = ((Hash) pk.get("H_2"));
		Hash H_3 = ((Hash) pk.get("H_3"));

		// Use H_1 to hash ID
		byte[] byte_H_1_ID = H_1.hash(ID.getBytes());
		Element h_ID = Utils.bytes2element(byte_H_1_ID, "G1").getImmutable();

		Element r_1 = pairing.getZr().newRandomElement().getImmutable();
		Element r_2 = pairing.getZr().newRandomElement().getImmutable();
		Element r_3 = pairing.getZr().newRandomElement().getImmutable();

		// Compute C_1,C_2,C_4
		Element C_1 = g.powZn(r_1).getImmutable();
		Element C_2 = g.powZn(r_2).getImmutable();
		Element C_4 = g.powZn(r_3).getImmutable();

		// Compute C_3
		Element U_1_r_2 = pairing.pairing(h_ID, g_1).powZn(r_2).getImmutable();

		Element elem_m = Utils.bytes2element(m, "G1");
		elem_m.powZn(r_1);
		Element C_3 = elem_m.duplicate().getImmutable();

		byte[] byte_U_1_r_2 = H_2.hash(U_1_r_2.toBytes());
		Element elem_U_1_r_2 = Utils.bytes2element(byte_U_1_r_2, "G1").getImmutable();
		C_3 = C_3.mul(elem_U_1_r_2).getImmutable();

		// Compute C_5
		Element U_2_r_3 = pairing.pairing(h_ID, g_2).powZn(r_3).getImmutable();

		byte[] byte_U_2_r_3 = H_3.hash(U_2_r_3.toBytes());
		byte[] m_concate_r_1 = Utils.addBytes(m, r_1.toBytes());

		// Make m_concate_z be the standard length
		byte[] zero = null;
		try {
			zero = "0".getBytes("utf-8");
			zero = H_3.hash(zero);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] m_concate_r_1_std = Utils.byte_array_Xor(Utils.byte_array_Xor(zero, m_concate_r_1), zero);
		byte[] C_5 = Utils.byte_array_Xor(m_concate_r_1_std, byte_U_2_r_3);

		Map<String, Object> ct = new HashMap<String, Object>();
		ct.put("type", "ct");
		ct.put("ID", ID);
		ct.put("C_1", C_1);
		ct.put("C_2", C_2);
		ct.put("C_3", C_3);
		ct.put("C_4", C_4);
		ct.put("C_5", C_5);

		// Evaluate
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return ct;
	}

	public Object test(Map<String, Object> pk, Map<String, Object> ct_A, Map<String, Object> td_A,
			Map<String, Object> ct_B, Map<String, Object> td_B) {

		long startTime = System.nanoTime();

		if (ct_A == null || !(((String) ct_A.get("type")).equals("ct")) || ct_B == null
				|| !(((String) ct_B.get("type")).equals("ct"))) {
			System.out.println("The input ct_A or ct_B is error!");
			return null;
		}

		// obtain C_A_1
		Element C_A_1 = ((Element) ct_A.get("C_1")).duplicate().getImmutable();

		// obtain C_B_1
		Element C_B_1 = ((Element) ct_B.get("C_1")).duplicate().getImmutable();

		Element delta_A = IBEET.compute(pk, ct_A, td_A, pairing);
		Element delta_B = IBEET.compute(pk, ct_B, td_B, pairing);

		if (delta_A == null || delta_B == null) {
			return false;
		}
		Element equ_left = pairing.pairing(delta_A, C_B_1).getImmutable();
		Element equ_right = pairing.pairing(delta_B, C_A_1).getImmutable();

		if (equ_left.equals(equ_right)) {
			long endTime = System.nanoTime();
			System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
			return true;
		} else {
			return false;
		}
	}

	public byte[] decrypt(Map<String, Object> pk, Map<String, Object> ct, Map<String, Object> sk) {

		long startTime = System.nanoTime();

		if (pk == null || !(((String) pk.get("type")).equals("pk"))) {
			System.out.println("The input pk is error!");
			return null;
		}

		if (sk == null || !(((String) sk.get("type")).equals("sk"))) {
			System.out.println("The input sk is error!");
			return null;
		}

		if (ct == null || !(((String) ct.get("type")).equals("ct"))) {
			System.out.println("The input ct is error!");
			return null;
		}

		// Condition
		String ID = (String) sk.get("ID");
		String ID_prime = (String) ct.get("ID");
		if (!ID.equals(ID_prime)) {
			System.out.println("ID is not equal to ID_prime!");
			return null;
		}

		// Parse pk
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Hash H_2 = ((Hash) pk.get("H_2"));
		Hash H_3 = ((Hash) pk.get("H_3"));

		// Parse sk
		Element K_1 = ((Element) sk.get("K_1")).duplicate().getImmutable();
		Element K_2 = ((Element) sk.get("K_2")).duplicate().getImmutable();

		// Parse ct
		Element C_1 = ((Element) ct.get("C_1")).duplicate().getImmutable();
		Element C_2 = ((Element) ct.get("C_2")).duplicate().getImmutable();
		Element C_3 = ((Element) ct.get("C_3")).duplicate().getImmutable();
		Element C_4 = ((Element) ct.get("C_4")).duplicate().getImmutable();
		byte[] C_5 = (byte[]) ct.get("C_5");
		Element B = pairing.pairing(K_2, C_4).getImmutable();
		Element B_prime = pairing.pairing(K_1, C_2).getImmutable();

		byte[] H3_B = H_3.hash(B.toBytes());
		byte[] byte_m_concate_r1 = Utils.byte_array_Xor(C_5, H3_B);
		Element elem_in_Zr = pairing.getZr().newOneElement();
		int r1_length = elem_in_Zr.toBytes().length;
		byte[] m = Utils.byteSpliter(byte_m_concate_r1, r1_length)[0];
		byte[] byte_r1 = Utils.byteSpliter(byte_m_concate_r1, r1_length)[1];

		Element m_G1 = Utils.bytes2element(m, "G1").getImmutable();

		Element r_1 = pairing.getZr().newElementFromBytes(byte_r1).getImmutable();
		byte[] H2_byte_B_prime = H_2.hash(B_prime.toBytes());

		Element H2_B_prime_G1 = Utils.bytes2element(H2_byte_B_prime, "G1").getImmutable();

		Element equ_right_one = m_G1.powZn(r_1).mul(H2_B_prime_G1).getImmutable();
		Element equ_right_two = g.powZn(r_1).getImmutable();

		if (C_3.equals(equ_right_one) && C_1.equals(equ_right_two)) {
			long endTime = System.nanoTime();
			System.out.println(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
			return m;
		} else {
			System.out.println("The equations do not hold!");
			return null;
		}
	}

	private static Element compute(Map<String, Object> pk, Map<String, Object> ct, Map<String, Object> td,
			Pairing pairing) {
		// obtain td
		String ID = (String) td.get("ID");
		Element D_1 = ((Element) td.get("D_1")).duplicate().getImmutable();

		// obtain ct
		String ID_prime = (String) ct.get("ID");
		Element C_2 = ((Element) ct.get("C_2")).duplicate().getImmutable();
		Element C_3 = ((Element) ct.get("C_3")).duplicate().getImmutable();

		// obtain pp
		Hash H_2 = (Hash) pk.get("H_2");

		// Condition
		if (!ID.equals(ID_prime)) {
			System.out.println("ID is not equal to ID_prime!");
			return null;
		}

		Element B_prime = pairing.pairing(D_1, C_2).getImmutable();

		byte[] H2_byte_B_prime = H_2.hash(B_prime.toBytes());
		Element H2_B_prime_G1 = Utils.bytes2element(H2_byte_B_prime, "G1").getImmutable();

		Element delta = C_3.div(H2_B_prime_G1).getImmutable();

		return delta;

	}
}
