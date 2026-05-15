package scheme;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import utils.Hash;
import utils.Function;
import utils.Rule;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;


/**
*  Created by cleverli on 2022.9.19
*  Modified by cleverli on 2024.1.23
*  Modified by cleverli on 2025.9.12
*  Modified by cleverli on 2026.4.23  
**/

public class IBEET_FTBA_TypeD {
	
	private Pairing pairing = PairingFactory.getPairing("curves/d224.properties");

	//Setup algorithm
	public List<Map<String, Object>> setup(int l) {
		return setup(l, null);
	}

	// This overload allows the caller to attach an optional vector rule
	// to the public parameters, so later trapdoor/ciphertext matches can
	// be checked against extra semantic constraints.
	public List<Map<String, Object>> setup(int l, Rule vectorRule) {

		// long startTime = System.nanoTime();
		 
		// The rule can describe only positions that already exist in the scheme vector.
		if (vectorRule != null && vectorRule.length() > l) {
			throw new IllegalArgumentException("The vector rule length cannot be larger than l.");
		}

		// Pick hash functions
		Hash H = new Hash("SHA-1");
		Hash H_1 = new Hash("SHA-1");
		Hash H_2 = new Hash("SHA-1");

		// Generate the master key
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		Element alpha_prime = pairing.getZr().newRandomElement().getImmutable();
		
		// Construct the master key
		Map<String, Object> masterKey = new HashMap<String, Object>();
		masterKey.put("type", "msk");
		masterKey.put("alpha", alpha);
		masterKey.put("alpha_prime", alpha_prime);

		// Generate public parameters
		
		//G1
		Element g = pairing.getG1().newRandomElement().getImmutable();
		Element g_1 = g.powZn(alpha).getImmutable();
		Element g_prime_1 = g.powZn(alpha_prime).getImmutable();
		
		//G2
		Element g_2 = pairing.getG2().newRandomElement().getImmutable();
		Element h = pairing.getG2().newRandomElement().getImmutable();
		Element h_prime = pairing.getG2().newRandomElement().getImmutable();
		Element h_prime_2 = pairing.getG2().newRandomElement().getImmutable();
		Element h_prime_3 = pairing.getG2().newRandomElement().getImmutable();
		
		
		//Construct public parameters
		Map<String, Object> publicKey = new HashMap<String, Object>();
		publicKey.put("type", "pk");
		publicKey.put("l", l);
		
		// Store the optional rule inside the public key so every later operation
		// can read the same validation policy from the same place.
		publicKey.put("vectorRule", vectorRule);

		publicKey.put("g", g);
		publicKey.put("g_2", g_2);
		publicKey.put("h", h);
		publicKey.put("h_prime", h_prime);
		publicKey.put("h_prime_2", h_prime_2);
		publicKey.put("h_prime_3", h_prime_3);
		publicKey.put("g_1", g_1);
		publicKey.put("g_prime_1", g_prime_1);

		publicKey.put("H", H);
		publicKey.put("H_1", H_1);
		publicKey.put("H_2", H_2);

		//G2
		for (int i = 0; i <= l; i++) {
			Element h_i = pairing.getG2().newRandomElement().getImmutable();
			Element u_i = h_i.powZn(alpha).getImmutable();
			publicKey.put("h_" + i, h_i);
			publicKey.put("u_" + i, u_i);
		}
		
		// Set the key array
		List<Map<String, Object>> res = new ArrayList<Map<String, Object>>();
		res.add(0, publicKey);
		res.add(1, masterKey);

		
		// Evaluate running time
		// long endTime = System.nanoTime();
		// System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		   return res;
	}

	//Key generation algorithm	
	public Map<String, Object> keyGen(Map<String, Object> pk, Map<String, Object> msk, String ID) {

		// long startTime = System.nanoTime();

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

		Element alpha = ((Element) msk.get("alpha")).duplicate().getImmutable();
		Element alpha_prime = ((Element) msk.get("alpha_prime")).duplicate().getImmutable();

		Element r = pairing.getZr().newRandomElement().getImmutable();
		Element r_prime = pairing.getZr().newRandomElement().getImmutable();
		Element r_prime_2 = pairing.getZr().newRandomElement().getImmutable();
		Element r_prime_3 = pairing.getZr().newRandomElement().getImmutable();

		Element h = ((Element) pk.get("h")).duplicate().getImmutable();
		Element g = ((Element) pk.get("g_2")).duplicate().getImmutable();
		Element h_prime = ((Element) pk.get("h_prime")).duplicate().getImmutable();
		Element h_prime_2 = ((Element) pk.get("h_prime_2")).duplicate().getImmutable();
		Element h_prime_3 = ((Element) pk.get("h_prime_3")).duplicate().getImmutable();
		
		// Hash
		Element elem_ID = Function.bytes2element(ID.getBytes(), "Zr",pairing).getImmutable();

		Element one = pairing.getZr().newOneElement().getImmutable();
		Element K_1 = (h.mul(g.powZn(r.negate()))).powZn(one.div(alpha.add(elem_ID.negate()))).getImmutable();
		Element K_1_prime = (h_prime.mul(g.powZn(r_prime.negate()))).powZn(one.div(alpha_prime.add(elem_ID.negate())))
				.getImmutable();
		Element K_2_prime = (h_prime_2.mul(g.powZn(r_prime_2.negate()))).powZn(one.div(alpha_prime.add(elem_ID.negate())))
				.getImmutable();
		Element K_3_prime = (h_prime_3.mul(g.powZn(r_prime_3.negate()))).powZn(one.div(alpha_prime.add(elem_ID.negate())))
				.getImmutable();

		// Set the secret key
		Map<String, Object> sk = new HashMap<String, Object>();
		sk.put("type", "sk");
		sk.put("ID", ID);
		sk.put("r", r);
		sk.put("r_prime", r_prime);
		sk.put("r_prime_2", r_prime_2);
		sk.put("r_prime_3", r_prime_3);
		sk.put("K_1", K_1);
		sk.put("K_1_prime", K_1_prime);
		sk.put("K_2_prime", K_2_prime);
		sk.put("K_3_prime", K_3_prime);

		// Evaluate running time
		// long endTime = System.nanoTime();
//		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return sk;
	}

	//Trapdoor algorithm
	public Map<String, Object> trapdoor(Map<String, Object> pk, Map<String, Object> sk, String[] P) {

		// long startTime = System.nanoTime();

		if (pk == null || !(((String) pk.get("type")).equals("pk"))) {
			System.out.println("The input pk is error!");
			return null;
		}

		if (sk == null || !(((String) sk.get("type")).equals("sk"))) {
			System.out.println("The input sk is error!");
			return null;
		}

		if (P == null || P.length == 0) {
			System.out.println("The input pattern P is error!");
			return null;
		}

		Element K_1 = ((Element) sk.get("K_1")).duplicate().getImmutable();
		Element r = ((Element) sk.get("r")).duplicate().getImmutable();
		String ID = (String) sk.get("ID");

		Element elem_ID = Function.bytes2element(ID.getBytes(), "Zr", pairing).getImmutable();

		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
	
		// int l = ((int)pk.get("l"));

		// Set the trapdoor
		Map<String, Object> td = new HashMap<String, Object>();
		td.put("type", "td");
		td.put("ID", ID);
		td.put("P", P);
		td.put("r", r);

		Element t = pairing.getZr().newRandomElement().getImmutable();
		Element D_2 = (g_1.mul(g.powZn(elem_ID.negate()))).powZn(t).getImmutable();
		Element D_1 = pairing.getG2().newOneElement().getImmutable();
		
		//Add the calculation of index 0
		Element h_0 = ((Element) pk.get("h_0")).duplicate().getImmutable();
		Element u_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();
		D_1 = D_1.mul((u_0.mul(h_0.powZn(elem_ID.negate()))).powZn(elem_ID)).getImmutable();

		for (int i = 1; i <= P.length; i++) {
			Element h_i = ((Element) pk.get("h_" + i)).duplicate().getImmutable();
			Element u_i = ((Element) pk.get("u_" + i)).duplicate().getImmutable();
			if (P[i-1].equals("*")) {
				Element D_i = (u_i.mul(h_i.powZn(elem_ID.negate()))).powZn(t).getImmutable();
				td.put("D_" + i+"_prime", D_i);
			} else {
				Element elem_P_i = Function.bytes2element(P[i-1].getBytes(), "Zr", pairing).getImmutable();
				D_1 = D_1.mul((u_i.mul(h_i.powZn(elem_ID.negate()))).powZn(elem_P_i)).getImmutable();
			}
		}
		D_1 = K_1.mul(D_1.powZn(t)).getImmutable();
		td.put("D_1", D_1);
		td.put("D_2", D_2);

		// Evaluate running time
		// long endTime = System.nanoTime();
		// System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return td;
	}

	//Encryption algorithm
	public Map<String, Object> encrypt(Map<String, Object> pk, String ID, byte[] m, String[] T) {

		// long startTime = System.nanoTime();

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

		if (T == null || T.length == 0) {
			System.out.println("The input T is error!");
			return null;
		}

		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element g_prime_1 = ((Element) pk.get("g_prime_1")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();
		
		Element h = ((Element) pk.get("h")).duplicate().getImmutable();
		Element h_prime = ((Element) pk.get("h_prime")).duplicate().getImmutable();
		Element h_prime_2 = ((Element) pk.get("h_prime_2")).duplicate().getImmutable();
		Element h_prime_3 = ((Element) pk.get("h_prime_3")).duplicate().getImmutable();
		Hash H = ((Hash) pk.get("H"));
		Hash H_1 = ((Hash) pk.get("H_1"));
		Hash H_2 = ((Hash) pk.get("H_2"));

		Element s = pairing.getZr().newRandomElement().getImmutable();
		Element s_prime = pairing.getZr().newRandomElement().getImmutable();
		Element z = pairing.getZr().newRandomElement().getImmutable();

		Element elem_ID = Function.bytes2element(ID.getBytes(), "Zr", pairing).getImmutable();

		Element C_0 = g.powZn(z).getImmutable();
		Element C_1 = g_1.powZn(s).mul(g.powZn((s.mul(elem_ID)).negate())).getImmutable();
		Element C_1_prime = g_prime_1.powZn(s_prime).mul(g.powZn((s_prime.mul(elem_ID)).negate())).getImmutable();
		Element C_2 = pairing.pairing(g, g_2).powZn(s).getImmutable();
		Element C_2_prime = pairing.pairing(g, g_2).powZn(s_prime).getImmutable();

		// Compute C_3
		Element elem_m = Function.bytes2element(m, "G2", pairing);
		
		//For test
		//System.out.println("m:"+ elem_m.toString());
		
		elem_m.powZn(z);
		Element C_3 = elem_m.duplicate().getImmutable();

		Element e_gh_s = pairing.pairing(g, h).powZn(s).getImmutable();
		byte[] byte_e_gh_s = H_1.hash(e_gh_s.toBytes());
		Element elem_e_gh_s = Function.bytes2element(byte_e_gh_s, "G2", pairing).getImmutable();
		C_3 = C_3.mul(elem_e_gh_s).getImmutable();

		// Compute C_4
		Element C_4 = pairing.getG2().newOneElement().getImmutable();
		
		//Add the calculation of index 0
		Element h_0 = ((Element) pk.get("h_0")).duplicate().getImmutable();
		Element u_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();
		C_4 = C_4.mul((u_0.mul(h_0.powZn(elem_ID.negate()))).powZn(elem_ID.mul(s))).getImmutable();
		
		for (int i = 1; i <= T.length; i++) {
			Element h_i = ((Element) pk.get("h_" + i)).duplicate().getImmutable();
			Element u_i = ((Element) pk.get("u_" + i)).duplicate().getImmutable();
			Element elem_T_i = Function.bytes2element(T[i-1].getBytes(), "Zr", pairing).getImmutable();
			C_4 = C_4.mul((u_i.mul(h_i.powZn(elem_ID.negate()))).powZn(elem_T_i.mul(s))).getImmutable();
		}

		// Compute C_3_prime
		Element e_gh_prime_s = pairing.pairing(g, h_prime).powZn(s_prime).getImmutable();
		byte[] byte_e_gh_prime_s = H_2.hash(e_gh_prime_s.toBytes());
		byte[] m_concate_z = Function.addBytes(m, z.toBytes());

		// Make m_concate_z be the standard length
		byte[] zero = null;
		try {
			zero = "0".getBytes("utf-8");
			zero = H_2.hash(zero);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] m_concate_z_std = Function.byte_array_Xor(Function.byte_array_Xor(zero, m_concate_z), zero);
		byte[] C_3_prime = Function.byte_array_Xor(m_concate_z_std, byte_e_gh_prime_s);

		String str_input = C_0.toString() + C_1.toString() + C_1_prime.toString() + C_2.toString() + C_2_prime.toString() + C_3.toString() + C_4.toString();
		byte[] byte_input = Function.addBytes(str_input.getBytes(), C_3_prime);
		byte[] byte_w = H.hash(byte_input);
		Element w = Function.bytes2element(byte_w, "Zr", pairing).getImmutable();
		
		
		// Compute C_4_prime
		Element C_4_prime = pairing.pairing(g, h_prime_2).powZn(s_prime).mul(pairing.pairing(g, h_prime_3).powZn(s_prime.mul(w))).getImmutable();

		Map<String, Object> ct = new HashMap<String, Object>();
		ct.put("type", "ct");
		ct.put("ID", ID);
		ct.put("T", T);
		ct.put("C_0", C_0);
		ct.put("C_1", C_1);
		ct.put("C_1_prime", C_1_prime);
		ct.put("C_2", C_2);
		ct.put("C_2_prime", C_2_prime);
		ct.put("C_3", C_3);
		ct.put("C_4", C_4);
		ct.put("C_3_prime", C_3_prime);
		ct.put("C_4_prime", C_4_prime);

		// Evaluate running time
		// long endTime = System.nanoTime();
		// System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return ct;
	}
	
	//Test algorithm
	public Object test(Map<String, Object> pk, Map<String, Object> ct_A, Map<String, Object> td_A, Map<String, Object> ct_B, Map<String, Object> td_B){
		
		// long startTime = System.nanoTime();
	
		if(ct_A== null || !(((String)ct_A.get("type")).equals("ct")) || ct_B == null || !(((String)ct_B.get("type")).equals("ct"))) {
			System.out.println("The input ct_A or ct_B is error!");
			return null;
		}

		// The test logic also expects two well-formed trapdoors.
		if(td_A== null || !(((String)td_A.get("type")).equals("td")) || td_B == null || !(((String)td_B.get("type")).equals("td"))) {
			System.out.println("The input td_A or td_B is error!");
			return null;
		}

		// Run all prefix and rule checks once before the expensive pairing equations.
		// This prevents the core comparison from accepting a syntactically matched
		// pair whose wildcard positions violate the extra vector rule.
		List<String> matchIssues = new ArrayList<String>();
		matchIssues.addAll(matchIssues(pk, ct_A, td_A));
		matchIssues.addAll(matchIssues(pk, ct_B, td_B));
		if (!matchIssues.isEmpty()) {
			printMatchIssues(matchIssues);
			return false;
		}
		
		//obtain C_A_1
		Element C_A_0 = ((Element)ct_A.get("C_0")).duplicate().getImmutable();
		
		//obtain C_B_1
		Element C_B_0 = ((Element)ct_B.get("C_0")).duplicate().getImmutable();
		
		Element delta_A = IBEET_FTBA_TypeD.compute(pk, ct_A, td_A, pairing);
		Element delta_B = IBEET_FTBA_TypeD.compute(pk, ct_B, td_B, pairing);

		if(delta_A==null||delta_B==null){
			return false;
		}
		
		Element equ_left = pairing.pairing(C_B_0,delta_A).getImmutable();
		Element equ_right = pairing.pairing(C_A_0,delta_B).getImmutable();
		
		if(equ_left.equals(equ_right)){
			
			// Evaluate running time
			// long endTime = System.nanoTime();
			// System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");
			return true;
		}
		else {
			return false;
		}		
	}

	// Collect all matching problems for one ciphertext/trapdoor pair.
	// The check is split out so the same validation path can be reused
	// for both inputs of test(...).
	private static List<String> matchIssues(Map<String, Object> pk, Map<String, Object> ct, Map<String, Object> td) {
		List<String> issues = new ArrayList<String>();
		String ID = (String) td.get("ID");
		String ID_prime = (String) ct.get("ID");
		String[] P = (String[]) td.get("P");
		String[] T = (String[]) ct.get("T");

		// First keep the original identity and wildcard-prefix requirement.
		if (!(ID.equals(ID_prime) && Function.wildPrefix(T, P))) {
			issues.add("Not matching!");
			return issues;
		}

		// If no rule is attached to the public key, the old matching behavior stays unchanged.
		Object vectorRuleObject = pk.get("vectorRule");
		if (!(vectorRuleObject instanceof Rule)) {
			return issues;
		}

		// Ask the rule to validate the concrete values that fill wildcard positions.
		Rule vectorRule = (Rule) vectorRuleObject;
		Rule.ValidationResult result = vectorRule.validateWildcardMatch(P, T);
		if (!result.isValid()) {
			issues.add(summarizeRuleIssue(vectorRule, T, result, "IBEET_FTBA_TypeD"));
		}
		return issues;
	}

	// Build one concise summary message for all invalid indexes found in a match.
	private static String summarizeRuleIssue(Rule vectorRule, String[] target, Rule.ValidationResult result, String schemeName) {
		List<Integer> indices = new ArrayList<Integer>();
		for (Rule.Violation violation : result.violations()) {
			Integer index = violation.index();
			if (index != null && !indices.contains(index)) {
				indices.add(index);
			}
		}

		if (!indices.isEmpty()) {
			return "The " + vectorRule.vectorName() + " vector " + formatVectorForMessage(vectorRule, target)
					+ " is invalid. [" + schemeName + ", Error Index:" + joinIndices(indices) + "]";
		}
		return schemeName + " rule validation failed: " + String.join("; ", result.errors());
	}

	// Format the concrete target vector in a compact human-readable form.
	private static String formatVectorForMessage(Rule vectorRule, String[] target) {
		if (target == null) {
			return "null";
		}
		if (target.length == 5
				&& "year".equals(vectorRule.meaningOf(0))
				&& "month".equals(vectorRule.meaningOf(1))
				&& "day".equals(vectorRule.meaningOf(2))
				&& "hour".equals(vectorRule.meaningOf(3))
				&& "minute".equals(vectorRule.meaningOf(4))) {
			return target[0] + "-" + target[1] + "-" + target[2] + " " + target[3] + ":" + target[4];
		}

		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < target.length; i++) {
			if (i > 0) {
				builder.append(" ");
			}
			builder.append(target[i]);
		}
		return builder.toString();
	}

	// Join all invalid indexes into the format 1,2,3.
	private static String joinIndices(List<Integer> indices) {
		StringBuilder builder = new StringBuilder();
		for (int i = 0; i < indices.size(); i++) {
			if (i > 0) {
				builder.append(",");
			}
			builder.append(indices.get(i));
		}
		return builder.toString();
	}

	// Remove duplicate messages before printing, so one failed rule
	// does not flood the console when both comparisons hit the same issue.
	private static void printMatchIssues(List<String> issues) {
		List<String> uniqueIssues = new ArrayList<String>();
		for (String issue : issues) {
			if (!uniqueIssues.contains(issue)) {
				uniqueIssues.add(issue);
			}
		}
		for (String issue : uniqueIssues) {
			System.out.println(issue);
		}
	}

	//Decryption algorithm
	public byte[] decrypt(Map<String, Object> pk, Map<String, Object> ct, Map<String, Object> sk) {

		// long startTime = System.nanoTime();

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

		//Condition one
		String ID = (String) sk.get("ID");
		String ID_prime = (String) ct.get("ID");
		if(!ID.equals(ID_prime)){
			System.out.println("Not matching!");
			return null;
		}
		
		
		// Parse pk
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Hash H = ((Hash) pk.get("H"));
		Hash H_1 = ((Hash) pk.get("H_1"));
		Hash H_2 = ((Hash) pk.get("H_2"));
		
		// Parse sk
		Element K_1 = ((Element) sk.get("K_1")).duplicate().getImmutable();
		Element r = ((Element) sk.get("r")).duplicate().getImmutable();
		Element K_1_prime = ((Element) sk.get("K_1_prime")).duplicate().getImmutable();
		Element r_prime = ((Element) sk.get("r_prime")).duplicate().getImmutable();
		Element K_2_prime = ((Element) sk.get("K_2_prime")).duplicate().getImmutable();
		Element r_prime_2 = ((Element) sk.get("r_prime_2")).duplicate().getImmutable();
		Element K_3_prime = ((Element) sk.get("K_3_prime")).duplicate().getImmutable();
		Element r_prime_3 = ((Element) sk.get("r_prime_3")).duplicate().getImmutable();

		// Parse ct
		Element C_0 = ((Element) ct.get("C_0")).duplicate().getImmutable();
		Element C_1 = ((Element) ct.get("C_1")).duplicate().getImmutable();
		Element C_1_prime = ((Element) ct.get("C_1_prime")).duplicate().getImmutable();
		Element C_2 = ((Element) ct.get("C_2")).duplicate().getImmutable();
		Element C_2_prime = ((Element) ct.get("C_2_prime")).duplicate().getImmutable();
		Element C_3 = ((Element) ct.get("C_3")).duplicate().getImmutable();
		Element C_4 = ((Element) ct.get("C_4")).duplicate().getImmutable();
		byte[] C_3_prime = (byte[]) ct.get("C_3_prime");
		Element C_4_prime = ((Element) ct.get("C_4_prime")).duplicate().getImmutable();
		
//		Element elem_ID = Function.bytes2element(ID.getBytes(), "Zr").getImmutable(); 
		
		//Condition two
		//Compute w
		String str_input = C_0.toString() + C_1.toString() + C_1_prime.toString() + C_2.toString() + C_2_prime.toString() + C_3.toString() + C_4.toString();
		byte[] byte_input = Function.addBytes(str_input.getBytes(), C_3_prime);
		byte[] byte_w = H.hash(byte_input);
		Element w = Function.bytes2element(byte_w, "Zr",pairing).getImmutable();
		
		Element left = pairing.pairing(C_1_prime, K_2_prime.mul(K_3_prime.powZn(w))).mul(C_2_prime.powZn(r_prime_2.add(r_prime_3.mul(w)))).getImmutable();
		Element right = C_4_prime.duplicate().getImmutable();
		if(!left.equals(right)){
			System.out.println("Fail to pass the ciphertext validity test!");
			return null;
		}
		
		Element B = pairing.pairing(C_1, K_1).mul(C_2.powZn(r)).getImmutable();
		Element B_prime = pairing.pairing(C_1_prime, K_1_prime).mul(C_2_prime.powZn(r_prime)).getImmutable();
		byte[] H2_B_prime = H_2.hash(B_prime.toBytes());
		byte[] byte_m_concate_z = Function.byte_array_Xor(C_3_prime, H2_B_prime);
		int z_length = r.toBytes().length;
		byte[] m = Function.byteSpliter(byte_m_concate_z, z_length)[0];
		byte[] byte_z = Function.byteSpliter(byte_m_concate_z, z_length)[1];
		
		Element m_G2 = Function.bytes2element(m, "G2", pairing).getImmutable();
		
		Element z = pairing.getZr().newElementFromBytes(byte_z).getImmutable();
		byte[] H1_byte_B = H_1.hash(B.toBytes());
		
		Element H1_byte_B_G2 = Function.bytes2element(H1_byte_B, "G2", pairing).getImmutable();
		
		Element equ_right_one = m_G2.powZn(z).mul(H1_byte_B_G2).getImmutable();
		Element equ_right_two = g.powZn(z).getImmutable();
		
		if (C_3.equals(equ_right_one) && C_0.equals(equ_right_two)) {
			
			// Evaluate the running time
			// long endTime = System.nanoTime();
			// System.out.println(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
			return m;
		} else {
			System.out.println("The equations do not hold!");
			return null;
		}
	}

	//Compute C_x \xor \cita type
	  private static Element compute(Map<String, Object> pk, Map<String, Object> ct, Map<String, Object> td, Pairing pairing) {
		  
		    //obtain td
		    String ID  = (String)td.get("ID");
			String[] P = (String[])td.get("P");
			Element D_1 = ((Element)td.get("D_1")).duplicate().getImmutable();
			Element D_2 = ((Element)td.get("D_2")).duplicate().getImmutable();
			Element r = ((Element)td.get("r")).duplicate().getImmutable();
					
		    //obtain ct
			String[] T = (String[])ct.get("T");
			String ID_prime  = (String)ct.get("ID");
			Element C_1 = ((Element)ct.get("C_1")).duplicate().getImmutable();
			Element C_2 = ((Element)ct.get("C_2")).duplicate().getImmutable();
			Element C_3 = ((Element)ct.get("C_3")).duplicate().getImmutable();
			Element C_4 = ((Element)ct.get("C_4")).duplicate().getImmutable();
			
			//obtain pp
			Hash H_1 = (Hash)pk.get("H_1");
					
			Element overline_D_1 = D_1.duplicate().getImmutable();
			
			ArrayList<Integer> SetI = Function.getIndexofWildcards(T.length, P);
			Iterator<Integer> ite = SetI.iterator();
			while(ite.hasNext()){
				int i = ite.next().intValue() + 1;
				Element D_i = ((Element)td.get("D_"+ i +"_prime")).duplicate().getImmutable();
				Element T_i = Function.bytes2element(T[i-1].getBytes(),"Zr", pairing).getImmutable();
				overline_D_1 = overline_D_1.mul(D_i.powZn(T_i));
			}
		
			Element B = (pairing.pairing(C_1, overline_D_1).mul(C_2.powZn(r))).div(pairing.pairing(D_2,C_4)).getImmutable();
			byte[] H1_byte_B = H_1.hash(B.toBytes());
			Element H1_B_G2 = Function.bytes2element(H1_byte_B, "G2", pairing).getImmutable();
			
			Element delta = C_3.div(H1_B_G2).getImmutable();
					
			return delta;
	  }
	  
}
