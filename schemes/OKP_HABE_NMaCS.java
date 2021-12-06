package schemes;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;
import abe.Attribute;
import abe.Policy;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import utils.PairingManager;
import utils.Polynomial;
import utils.Utils;

/**
 * @ClassName: OKP_HABE_NMaCS
 * @Description: (Implementation of "Hierarchical and non-monotonic key-policy
 *               attribute-based encryption and its application")
 * @author:cleverli2008
 * @date:2021/11/26
 */

public class OKP_HABE_NMaCS {

	private Pairing pairing = PairingManager.getDefaultPairing();

	public Map[] setup(int q) {

		long startTime = System.nanoTime();

		// Generate master key
		Element alpha = pairing.getZr().newRandomElement().getImmutable();

		Map<String, Object> masterKey = new HashMap<String, Object>();
		masterKey.put("alpha", alpha);
		masterKey.put("type", "msk");

		Map<String, Object> publicKey = new HashMap<String, Object>();

		// Generate public parameters
		Element g = pairing.getG1().newRandomElement().getImmutable();
		Element g_1 = pairing.getG1().newRandomElement().getImmutable();
		Element g_2 = pairing.getG2().newRandomElement().getImmutable();
		Element u_0 = pairing.getG1().newRandomElement().getImmutable();
		Element e_gg_alpha = pairing.pairing(g, g_2).powZn(alpha).getImmutable();

		publicKey.put("q", q);
		publicKey.put("g", g);
		publicKey.put("g_1", g_1);
		publicKey.put("g_2", g_2);
		publicKey.put("u_0", u_0);
		publicKey.put("e_gg_alpha", e_gg_alpha);
		publicKey.put("type", "pk");

		for (int i = 1; i <= q; i++) {
			Element u_i = pairing.getG1().newRandomElement().getImmutable();
			Element v_i = pairing.getG1().newRandomElement().getImmutable();
			Element h_i = pairing.getG1().newRandomElement().getImmutable();
			publicKey.put("u_" + i, u_i);
			publicKey.put("v_" + i, v_i);
			publicKey.put("h_" + i, h_i);
		}

		// set the key array
		Map<String, Object>[] res = new Map[2];
		res[0] = publicKey;
		res[1] = masterKey;

		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return res;
	}

	public Map<String, Object> authkeygen(Map<String, Object> pk, Map<String, Object> msk, String[] id_vector) {

		long startTime = System.nanoTime();
		if (id_vector == null || id_vector.length == 0) {
			System.out.println("The input ID vector is error!");
			return null;
		}

		Map<String, Object> ak = new HashMap<String, Object>();
		ak.put("id_vector", id_vector);

		Element alpha = ((Element) msk.get("alpha")).duplicate().getImmutable();
		ak.put("type", "ak");

		int j = id_vector.length;
		int q = (int) pk.get("q");
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();
		Element r = pairing.getZr().newRandomElement().getImmutable();
		Element K_0 = pairing.getG1().newOneElement().getImmutable();

		for (int i = 0; i < q; i++) {
			Element R_i = ((Element) pk.get("h_" + (i + 1))).duplicate().getImmutable();
			if (i < j) {
				R_i = R_i.powZn(pairing.getZr().newElementFromBytes(id_vector[i].getBytes())).getImmutable();
				K_0 = K_0.mul(R_i).getImmutable();
			} else {
				R_i = R_i.powZn(r).getImmutable();
				ak.put("R_" + (i + 1), R_i);
			}
			Element U_i = ((Element) pk.get("u_" + (i + 1))).duplicate().getImmutable();
			U_i = U_i.powZn(r).getImmutable();
			Element V_i = ((Element) pk.get("v_" + (i + 1))).duplicate().getImmutable();
			V_i = V_i.powZn(r).getImmutable();
			ak.put("U_" + (i + 1), U_i);
			ak.put("V_" + (i + 1), V_i);
		}
		Element U_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();
		U_0 = U_0.powZn(r).getImmutable();
		K_0 = g.powZn(alpha).mul((K_0.mul(g_1)).powZn(r)).getImmutable();
		Element K_1 = g_2.powZn(r).getImmutable();
		ak.put("K_0", K_0);
		ak.put("K_1", K_1);
		ak.put("U_0", U_0);

		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return ak;
	}

	public Map<String, Object> authdelegate(Map<String, Object> pk, Map<String, Object> ak, String id) {

		long startTime = System.nanoTime();
		if (id == null) {
			System.out.println("The input ID is error!");
			return null;
		}

		Map<String, Object> ak_new = new HashMap<String, Object>();
		ak_new.put("type", "ak");

		int q = (int) pk.get("q");
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();

		String[] id_vector = (String[]) ak.get("id_vector");
		int vec_len = id_vector.length;

		String[] id_vector_new = new String[vec_len + 1];
		for (int i = 0; i < vec_len + 1; i++) {
			if (i != vec_len)
				id_vector_new[i] = id_vector[i];
			else
				id_vector_new[i] = id;
		}
		ak_new.put("id_vector", id_vector_new);

		Element K_0 = ((Element) ak.get("K_0")).duplicate().getImmutable();
		Element K_1 = ((Element) ak.get("K_1")).duplicate().getImmutable();
		Element r_1 = pairing.getZr().newRandomElement().getImmutable();

		K_1 = K_1.mul(g_2.powZn(r_1)).getImmutable();
		ak_new.put("K_1", K_1);

		for (int i = vec_len; i < q; i++) {
			if (i != vec_len) {
				Element R_i = ((Element) ak.get("R_" + (i + 1))).duplicate().getImmutable();
				Element h_i = ((Element) pk.get("h_" + (i + 1))).duplicate().getImmutable();
				R_i = R_i.mul(h_i.powZn(r_1)).getImmutable();
				ak_new.put("R_" + (i + 1), R_i);
			}

			Element U_i = ((Element) ak.get("U_" + (i + 1))).duplicate().getImmutable();
			Element V_i = ((Element) ak.get("V_" + (i + 1))).duplicate().getImmutable();
			Element u_i = ((Element) pk.get("u_" + (i + 1))).duplicate().getImmutable();
			Element v_i = ((Element) pk.get("v_" + (i + 1))).duplicate().getImmutable();
			U_i = U_i.mul(u_i.powZn(r_1)).getImmutable();
			V_i = V_i.mul(v_i.powZn(r_1)).getImmutable();
			ak_new.put("U_" + (i + 1), U_i);
			ak_new.put("V_" + (i + 1), V_i);
		}

		Element R_j = ((Element) ak.get("R_" + (vec_len + 1))).duplicate().getImmutable();
		Element h_j = ((Element) pk.get("h_" + (vec_len + 1))).duplicate().getImmutable();

		Element u_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();
		Element U_0 = ((Element) ak.get("U_0")).duplicate().getImmutable();
		U_0 = U_0.mul(u_0.powZn(r_1)).getImmutable();
		ak_new.put("U_0", U_0);

		K_0 = K_0.mul((R_j).powZn(pairing.getZr().newElementFromBytes(id.getBytes()))).getImmutable();
		Element delta = pairing.getG1().newOneElement().getImmutable();

		for (int i = 0; i < vec_len; i++) {
			Element U_i = ((Element) ak.get("U_" + (i + 1))).duplicate().getImmutable();
			Element V_i = ((Element) ak.get("V_" + (i + 1))).duplicate().getImmutable();
			Element u_i = ((Element) pk.get("u_" + (i + 1))).duplicate().getImmutable();
			Element v_i = ((Element) pk.get("v_" + (i + 1))).duplicate().getImmutable();
			U_i = U_i.mul(u_i.powZn(r_1)).getImmutable();
			V_i = V_i.mul(v_i.powZn(r_1)).getImmutable();
			ak_new.put("U_" + (i + 1), U_i);
			ak_new.put("V_" + (i + 1), V_i);

			Element h_i = ((Element) pk.get("h_" + (i + 1))).duplicate().getImmutable();
			delta = delta.mul(h_i.powZn(pairing.getZr().newElementFromBytes(id_vector[i].getBytes()))).getImmutable();
		}
		delta = (delta.mul(g_1.mul(h_j.powZn(pairing.getZr().newElementFromBytes(id.getBytes()))))).powZn(r_1)
				.getImmutable();
		K_0 = K_0.mul(delta).getImmutable();
		ak_new.put("K_0", K_0);
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return ak_new;
	}

	public Map<String, Object> encrypt(Map<String, Object> pk, String[] id_vector, Attribute[] set_s, String message) {

		long startTime = System.nanoTime();
		if (id_vector == null || id_vector.length == 0 || set_s == null || set_s.length == 0) {
			System.out.println("The input ID vector or attribute set is error!");
			return null;
		}

		Map<String, Object> ct = new HashMap<String, Object>();
		ct.put("type", "ct");

		int q = (int) pk.get("q");
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();
		Element e_gg_alpha = ((Element) pk.get("e_gg_alpha")).duplicate().getImmutable();
		Element u_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();

		Element s = pairing.getZr().newRandomElement().getImmutable();

		Element m = pairing.getGT().newRandomElement().getImmutable();
//		System.out.println("message:" + m);
		Element C = m.mul((e_gg_alpha).powZn(s)).getImmutable();
		Element C_0 = g_2.powZn(s).getImmutable();

		ct.put("id_vector", id_vector);
		ct.put("set_s", set_s);
		ct.put("C", C);
		ct.put("C_0", C_0);

		int vec_len = id_vector.length;
		Element[] h = new Element[vec_len];
		Element C_3 = g_1.duplicate().getImmutable();

		for (int i = 0; i < vec_len; i++) {
			h[i] = ((Element) pk.get("h_" + (i + 1))).duplicate().getImmutable();
			C_3 = C_3.mul(h[i].powZn(pairing.getZr().newElementFromBytes(id_vector[i].getBytes()))).getImmutable();
		}
		C_3 = C_3.powZn(s).getImmutable();
		ct.put("C_3", C_3);

		int set_size = set_s.length;
		Element[] values = new Element[set_size];
		for (int i = 0; i < set_size; i++) {
			values[i] = pairing.getZr().newElementFromBytes(set_s[i].getAttrValue().getBytes()).negate().getImmutable();
		}

		Polynomial poly = new Polynomial();
		Element[] coeff = poly.computeCoefficient_opt(values);

		Element[] zero = new Element[q - set_size];
		for (int i = 0; i < q - set_size; i++) {
			zero[i] = pairing.getZr().newZeroElement().getImmutable();
		}
		Element[] a = (Element[]) Utils.addArrays(coeff, zero);
		Element C_1 = u_0.duplicate().getImmutable();
		Element C_2 = pairing.getG1().newOneElement().getImmutable();

		for (int i = 0; i < q; i++) {
			Element u_i = ((Element) pk.get("u_" + (i + 1))).duplicate().getImmutable();
			Element v_i = ((Element) pk.get("v_" + (i + 1))).duplicate().getImmutable();
			C_1 = C_1.mul(u_i.powZn(a[i])).getImmutable();
			C_2 = C_2.mul(v_i.powZn(a[i])).getImmutable();
		}

		C_1 = C_1.powZn(s).getImmutable();
		C_2 = C_2.powZn(s).getImmutable();
		ct.put("C_1", C_1);
		ct.put("C_2", C_2);

		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");

		return ct;
	}

	public Map<String, Object>[] userkeygen(Map<String, Object> pk, Map<String, Object> ak, String str_policy) {

		long startTime = System.nanoTime();
		if (str_policy == null) {
			System.out.println("The input policy is error!");
			return null;
		}

		Map<String, Object> sk = new HashMap<String, Object>();
		sk.put("type", "sk");
		sk.put("str_policy", str_policy);

		Map<String, Object> dk = new HashMap<String, Object>();
		sk.put("type", "dk");

		Policy policy = new Policy(str_policy);
		sk.put("policy", policy);

		int[][] matrix = policy.getMatrix();
		Map<Integer, String> rho = policy.getRho();
		if (matrix == null) {
			System.out.println("The matrix is empty!");
			return null;
		}

		// pre-computing
		String[] id_vector = (String[]) ak.get("id_vector");
		sk.put("id_vector", id_vector);
		int q = (int) pk.get("q");
		Element u_0 = ((Element) pk.get("u_0")).duplicate().getImmutable();
		Element u_1 = ((Element) pk.get("u_1")).duplicate().getImmutable();
		Element v_1 = ((Element) pk.get("v_1")).duplicate().getImmutable();
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element) pk.get("g_1")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();

		Element pre_term = g_1.duplicate().getImmutable();

		for (int i = 0; i < id_vector.length; i++) {
			Element h_i = ((Element) pk.get("h_" + (i + 1))).duplicate().getImmutable();
			pre_term = pre_term.mul(h_i.powZn(pairing.getZr().newElementFromBytes(id_vector[i].getBytes())))
					.getImmutable();
		}

		Element pre_term_non = pre_term.mul(u_0).getImmutable();
		Element pre_term_neg = pre_term.mul(v_1).getImmutable();

		Element K_0 = ((Element) ak.get("K_0")).duplicate().getImmutable();
		Element K_1 = ((Element) ak.get("K_1")).duplicate().getImmutable();
		Element U_0 = ((Element) ak.get("U_0")).duplicate().getImmutable();
		Element U_1 = ((Element) ak.get("U_1")).duplicate().getImmutable();
		Element V_1 = ((Element) ak.get("V_1")).duplicate().getImmutable();
		Element pre_term_two_non = K_0.mul(U_0).getImmutable();
		Element pre_term_two_neg = K_0.mul(V_1).getImmutable();

		Element[] y = new Element[matrix[0].length];
		for (int i = 1; i < y.length; i++) {
			y[i] = pairing.getZr().newRandomElement().getImmutable();
		}

		Element o = pairing.getZr().newRandomElement().getImmutable();
		dk.put("o", o);

		for (int tau = 0; tau < matrix.length; tau++) {
			Element r_tau = pairing.getZr().newRandomElement().getImmutable();
			String attr = rho.get(tau);
			String attr_val = Utils.splitAttribute(attr, ":")[1];
			Element share_term = pairing.getZr().newZeroElement().getImmutable();

			for (int j = 1; j < y.length; j++) {
				Element M_tau_j = pairing.getZr().newElement((int) matrix[tau][j]).getImmutable();
				share_term = share_term.add(y[j].mul(M_tau_j)).getImmutable();
			}
			Element M_tau_0 = pairing.getZr().newElement((int) matrix[tau][0]).getImmutable();

			if (attr_val.charAt(0) != '-') {
				Element K_tau_0_1 = g.powZn(share_term.div(o)).mul(pre_term_two_non.powZn(M_tau_0.div(o)))
						.mul(pre_term_non.powZn(r_tau)).getImmutable();
				Element K_tau_1_1 = K_1.powZn(M_tau_0.div(o)).mul(g_2.powZn(r_tau)).getImmutable();
				sk.put("K_" + tau + "_0_1", K_tau_0_1);
				sk.put("K_" + tau + "_1_1", K_tau_1_1);
			} else {
				Element K_tau_0_2 = g.powZn(share_term.div(o)).mul(pre_term_two_neg.powZn(M_tau_0.div(o)))
						.mul(pre_term_neg.powZn(r_tau)).getImmutable();
				Element K_tau_1_2 = K_1.powZn(M_tau_0.div(o)).mul(g_2.powZn(r_tau)).getImmutable();
				sk.put("K_" + tau + "_0_2", K_tau_0_2);
				sk.put("K_" + tau + "_1_2", K_tau_1_2);
			}

			Element x_tau = pairing.getZr().newElementFromBytes(attr_val.getBytes()).getImmutable();
			for (int i = 2; i <= q; i++) {
				Element exp = pairing.getZr().newElement(i - 1).getImmutable();
				if (attr_val.charAt(0) != '-') {
					Element U_i = ((Element) ak.get("U_" + i)).duplicate().getImmutable();
					Element u_i = ((Element) pk.get("u_" + i)).duplicate().getImmutable();
					Element K_tau_i_1 = ((U_1.powZn((x_tau.powZn(exp)).negate()).mul(U_i)).powZn(M_tau_0.div(o)))
							.mul((u_1.powZn((x_tau.powZn(exp)).negate()).mul(u_i)).powZn(r_tau)).getImmutable();
					sk.put("K_" + tau + "_" + i + "_1", K_tau_i_1);
				} else {

					Element V_i = ((Element) ak.get("V_" + i)).duplicate().getImmutable();
					Element v_i = ((Element) pk.get("v_" + i)).duplicate().getImmutable();
					Element K_tau_i_2 = ((V_1.powZn((x_tau.powZn(exp)).negate()).mul(V_i)).powZn(M_tau_0.div(o)))
							.mul((v_1.powZn((x_tau.powZn(exp)).negate()).mul(v_i)).powZn(r_tau)).getImmutable();
					sk.put("K_" + tau + "_" + i + "_2", K_tau_i_2);
				}
			}
		}
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		Map<String, Object>[] res = new Map[2];
		res[0] = sk;
		res[1] = dk;
		return res;
	}

	public Map<String, Object> transform(Map<String, Object> pk, Map<String, Object> ct, Map<String, Object> sk) {

		long startTime = System.nanoTime();

		int q = (int) pk.get("q");

		Map<String, Object> it = new HashMap<String, Object>();

		Policy policy = (Policy) sk.get("policy");
		sk.put("type", "it");

		int[][] matrix = policy.getMatrix();
		Map<Integer, String> rho = policy.getRho();

		Attribute[] attributes = (Attribute[]) ct.get("set_s");

		// compute set_NS
		Attribute[] set_NS = Utils.computeNS(attributes, rho);

		// attribute matching
		Map<Integer, Integer> setI = Utils.attributesMatching(set_NS, rho);

		// compute omega corresponding to set I
		Element[] omega = Utils.computeOmega(matrix, setI);
		if (omega == null) {
			return null;
		}

		Attribute[] attrsetI = new Attribute[setI.size()];
		int j = 0;
		for (Entry<Integer, Integer> entry : setI.entrySet()) {
			if (rho.get(entry.getKey()).equals(set_NS[entry.getValue()].toString())) {
				attrsetI[j] = set_NS[entry.getValue()];
				j++;
			} else
				System.out.println("SetI Error!");
		}

		int set_size = attributes.length;
		Element[] values = new Element[set_size];
		for (int i = 0; i < set_size; i++) {
			values[i] = pairing.getZr().newElementFromBytes(attributes[i].getAttrValue().getBytes()).negate()
					.getImmutable();
		}

		Polynomial poly = new Polynomial();
		Element[] coeff = poly.computeCoefficient(values);

		Element[] zero = new Element[q - set_size];
		for (int i = 0; i < q - set_size; i++) {
			zero[i] = pairing.getZr().newZeroElement().getImmutable();
		}
		Element[] a = (Element[]) Utils.addArrays(coeff, zero);

		Element C_0 = ((Element) ct.get("C_0")).duplicate().getImmutable();
		Element C_1 = ((Element) ct.get("C_1")).duplicate().getImmutable();
		Element C_3 = ((Element) ct.get("C_3")).duplicate().getImmutable();

		Element B = pairing.getGT().newOneElement().getImmutable();

		for (int i = 0; i < attrsetI.length; i++) {
			String attr = rho.get(i);
			String attr_val = Utils.splitAttribute(attr, ":")[1];
			if (attr_val.charAt(0) != '-') {
				Element K_i_1_1 = ((Element) sk.get("K_" + i + "_1_1")).duplicate().getImmutable();
				Element K_tilde_i_0_1 = ((Element) sk.get("K_" + i + "_0_1")).duplicate().getImmutable();
				for (int j_prime = 2; j_prime <= q; j_prime++) {
					Element K_i_j_1 = ((Element) sk.get("K_" + i + "_" + j_prime + "_1")).duplicate().getImmutable();
					K_tilde_i_0_1 = K_tilde_i_0_1.mul(K_i_j_1.powZn(a[j_prime - 1])).getImmutable();
				}
				B = B.mul((pairing.pairing(K_tilde_i_0_1, C_0).div(pairing.pairing(C_1.mul(C_3), K_i_1_1)))
						.powZn(omega[i])).getImmutable();
			} else {
				Element C_2 = ((Element) ct.get("C_2")).duplicate().getImmutable();
				Element K_i_0_2 = ((Element) sk.get("K_" + i + "_0_2")).duplicate().getImmutable();
				Element K_i_1_2 = ((Element) sk.get("K_" + i + "_1_2")).duplicate().getImmutable();
				Element K_tilde_i_2 = pairing.getG1().newOneElement().getImmutable();
				Element T_i = pairing.getG1().newOneElement().getImmutable();
				Element x_i = pairing.getZr().newElementFromBytes(attr_val.getBytes()).getImmutable();
				Element sum = poly.Product(x_i, coeff);
				for (int j_prime = 2; j_prime <= q; j_prime++) {
					Element K_i_j_2 = ((Element) sk.get("K_" + i + "_" + j_prime + "_2")).duplicate().getImmutable();
					K_tilde_i_2 = K_tilde_i_2.mul(K_i_j_2.powZn(a[j_prime - 1])).getImmutable();
				}
				T_i = (pairing.pairing(K_tilde_i_2, C_0).div(pairing.pairing(C_2, K_i_1_2)))
						.powZn(pairing.getZr().newOneElement().div(sum).negate()).getImmutable();
				B = B.mul((pairing.pairing(K_i_0_2, C_0).div(pairing.pairing(C_3, K_i_1_2).mul(T_i))).powZn(omega[i]))
						.getImmutable();
			}
		}
		Element C = ((Element) ct.get("C")).duplicate().getImmutable();
		it.put("B", B);
		it.put("C", C);
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float) ((endTime - startTime) / 1_000_000.0000)) + " ");
		return it;
	}

	public Element decrypt(Map<String, Object> it, Map<String, Object> dk) {

		long startTime = System.nanoTime();
		Element C = ((Element) it.get("C")).duplicate().getImmutable();
		Element B = ((Element) it.get("B")).duplicate().getImmutable();
		Element o = ((Element) dk.get("o")).duplicate().getImmutable();
		Element m = C.div(B.powZn(o)).getImmutable();
		long endTime = System.nanoTime();
		System.out.print(String.format("%.4f", (float) ((endTime - startTime) / 1_000_000.0000)));
		return m;
	}
}
