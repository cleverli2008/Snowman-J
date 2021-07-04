package schemes;

import java.lang.reflect.Array;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import abe.Attribute;
import abe.Threshold;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import utils.Hash;
import utils.Utils;

public class CP_HABEwCS {

	private Pairing pairing = PairingFactory.getPairing("schemes/a.properties");
	
	Map<String,Element> map_shares = new HashMap<String,Element>();
	
	public Map<String, Object>[] setup(Attribute[] universe) {
		
		long startTime = System.nanoTime();
		int N = universe.length;
		
		Attribute[] dummy_universe = new Attribute[N -1];
		for(int i = 0; i < N -1; i++){
			dummy_universe[i] = new Attribute("dummy_" + i,"dummy_" + i);
		}
		
		Attribute[] universe_all = (Attribute[]) CP_HABEwCS.addArrays(universe, dummy_universe);
		
		Hash H = new Hash("SHA-256");
		
		// Generate master key
		Element x = pairing.getZr().newRandomElement().getImmutable();
		
		Map<String, Object> masterKey = new HashMap<String, Object>();
		masterKey.put("type", "msk");
		masterKey.put("x", x);
		
		Map<String, Object> publicKey = new HashMap<String, Object>();
		publicKey.put("type", "pk");
		publicKey.put("universe", universe);
		publicKey.put("dummy_universe", dummy_universe);
		publicKey.put("universe_all", universe_all);
		
		// Generate public parameters
		Element g = pairing.getG1().newRandomElement().getImmutable();
		Element g_1 = g.powZn(x).getImmutable();
		
		Element g_2 = pairing.getG1().newRandomElement().getImmutable();
		Element Z = pairing.pairing(g_1, g_2).getImmutable();
		Element delta_1 = pairing.getG1().newRandomElement().getImmutable();
		Element delta_2 = pairing.getG1().newRandomElement().getImmutable();
		Element delta_3 = pairing.getG1().newRandomElement().getImmutable();
		
		Element h_0 = pairing.getG1().newRandomElement().getImmutable();
		
		publicKey.put("g", g);
		publicKey.put("g_1", g_1);
		publicKey.put("g_2", g_2);
		publicKey.put("h_0", h_0);
		publicKey.put("Z", Z);
		publicKey.put("delta_1", delta_1);
		publicKey.put("delta_2", delta_2);
		publicKey.put("delta_3", delta_3);
		publicKey.put("H", H);
	
		for(int i = 1; i <= 2 * N - 1 ; i++) {
			Element h_i = pairing.getG1().newRandomElement().getImmutable();
			publicKey.put("h_" + universe_all[i-1].toString(), h_i);
		}

		// set the key array
		Map<String, Object>[] res = new Map[2];
		res[0] = publicKey;
		res[1] = masterKey;
		
		long endTime = System.nanoTime();
//		System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");			
		return res;
	}
	
	public Map<String, Object> createDA(Map<String, Object> msk, Map<String, Object> pk, Attribute[] RA) {
		
		long startTime = System.nanoTime();
		
		Map<String, Object> sk_da = new HashMap<String, Object>();
		sk_da.put("type", "sk_da");
		sk_da.put("RA", RA);
		
		Attribute[] dummy_universe = (Attribute[]) pk.get("dummy_universe");
		Attribute[] universe = (Attribute[]) pk.get("universe");
		
		Attribute[] universe_all = (Attribute[]) pk.get("universe_all");
		
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();
		Element h_0 = ((Element) pk.get("h_0")).duplicate().getImmutable();
		
		Attribute[] A = (Attribute[]) CP_HABEwCS.addArrays(RA, dummy_universe);
		
		
		Element x = ((Element) msk.get("x")).duplicate().getImmutable();
        Element[] shares = Utils.shamirSS(A, universe.length-1, x);
        
        //for test
        for(int i = 0; i < A.length; i++){
        	map_shares.put(A[i].toString(), shares[i]);
        }
        
		for(int i = 0; i < A.length; i++){
			String attr = A[i].toString();
			Element r_i = pairing.getZr().newRandomElement().getImmutable();
			Element h_i = ((Element) pk.get("h_" + attr)).duplicate().getImmutable();
			Element a_i = g_2.powZn(shares[i]).mul((h_0.mul(h_i)).powZn(r_i)).getImmutable();
			
			Element b_i = g.powZn(r_i).getImmutable();
			sk_da.put("a_" + attr, a_i);
			sk_da.put("b_" + attr, b_i);
			for(int j = 0; j < 2 * universe.length - 1; j++){
				String temp_attr =  universe_all[j].toString();
				if(!temp_attr.equals(attr)) {
					Element h_j = ((Element) pk.get("h_" + temp_attr)).duplicate().getImmutable();
					Element c_i_j = h_j.powZn(r_i).getImmutable();
					sk_da.put("c_" + attr + "_" + temp_attr, c_i_j);
				}
			}
		}
		
		long endTime = System.nanoTime();
//		System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");			
		return sk_da;
	}
	
	public Map<String, Object> delegate(Map<String, Object> pk, Map<String, Object> sk_da, Attribute[] overline_RA) {
		
		long startTime = System.nanoTime();
		
		Map<String, Object> sk_da_u = new HashMap<String, Object>();
		sk_da_u.put("type", "sk_da_u");
		Attribute[] RA = (Attribute[]) sk_da.get("RA");
	
		
		boolean flag = CP_HABEwCS.isSubSet(RA, overline_RA);
		if(flag != true) {
			System.out.print("overline_RA is not a subset of RA!");	
			return null; 
		}
		sk_da_u.put("overline_RA", overline_RA);
		
		Attribute[] dummy_universe = (Attribute[]) pk.get("dummy_universe");
		Attribute[] universe = (Attribute[]) pk.get("universe");
		Attribute[] universe_all = (Attribute[]) pk.get("universe_all");
		
		Attribute[] overline_A = (Attribute[]) CP_HABEwCS.addArrays(overline_RA, dummy_universe);
		
		
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element h_0 = ((Element) pk.get("h_0")).duplicate().getImmutable();
		
		for(int i = 0; i < overline_A.length; i++){
			String attr = overline_A[i].toString();
			Element r_i_overline = pairing.getZr().newRandomElement().getImmutable();
			Element h_i = ((Element) pk.get("h_" + attr)).duplicate().getImmutable();
			Element a_i = ((Element) sk_da.get("a_" + attr)).duplicate().getImmutable();
			Element b_i = ((Element) sk_da.get("b_" + attr)).duplicate().getImmutable();
			Element a_i_overline = a_i.mul((h_0.mul(h_i)).powZn(r_i_overline)).getImmutable();
			Element b_i_overline = b_i.mul(g.powZn(r_i_overline)).getImmutable();
			sk_da_u.put("a_" + attr + "_overline", a_i_overline);
			sk_da_u.put("b_" + attr + "_overline", b_i_overline);
			for(int j = 0; j < 2 * universe.length - 1; j++){
				String temp_attr = universe_all[j].toString();
				if(!temp_attr.equals(attr)) {
					Element c_i_j = ((Element) sk_da.get("c_" + attr + "_" + temp_attr)).duplicate().getImmutable();
					Element h_j = ((Element) pk.get("h_" + temp_attr)).duplicate().getImmutable();
					Element c_i_j_overline = c_i_j.mul(h_j.powZn(r_i_overline)).getImmutable();
					sk_da_u.put("c_" + attr + "_" + temp_attr + "_overline", c_i_j_overline);
				}
			}
		}
		
		long endTime = System.nanoTime();
//		System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");			
		return sk_da_u;
	}
	
	
	public Map<String, Object> encrypt(Map<String, Object> pk, String message, Threshold threshold) {
		
		long startTime = System.nanoTime();
		
		Attribute[] setS = threshold.getsetS();
		int t = threshold.getTValue();
		
		Map<String, Object> ct = new HashMap<String, Object>();
		ct.put("type", "ct");
		ct.put("threshold", threshold);
				
		Attribute[] dummy_universe = (Attribute[]) pk.get("dummy_universe");
		Attribute[] W = new Attribute[dummy_universe.length-(t-1)];
		ct.put("W", W);
		
		System.arraycopy(dummy_universe, 0, W, 0, dummy_universe.length-(t-1));
		
		Attribute[] setS_new = (Attribute[]) CP_HABEwCS.addArrays(setS, W);
		
		Element Z = ((Element) pk.get("Z")).duplicate().getImmutable();
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element h_0 = ((Element) pk.get("h_0")).duplicate().getImmutable();
		Element delta_1= ((Element) pk.get("delta_1")).duplicate().getImmutable();
		Element delta_2= ((Element) pk.get("delta_2")).duplicate().getImmutable();
		Element delta_3= ((Element) pk.get("delta_3")).duplicate().getImmutable();
		Hash H= (Hash)pk.get("H");
		
		Element s = pairing.getZr().newRandomElement().getImmutable();
		Element r = pairing.getZr().newRandomElement().getImmutable();
		ct.put("r", r);
		
		byte[] message_bytes = message.getBytes();
		Element m = pairing.getGT().newElementFromHash(message_bytes, 0,  message_bytes.length);
//      System.out.println("message:" + m);
		Element C_0 = m.mul(Z.powZn(s)).getImmutable();
		Element C_1 = g.powZn(s).getImmutable();
		ct.put("C_0", C_0);
		ct.put("C_1", C_1);
		
		Element C_2 = h_0.duplicate().getImmutable();
		for(int i = 0; i < setS_new.length; i++){
			String attr = setS_new[i].toString();
			Element h_i = ((Element) pk.get("h_" + attr)).duplicate().getImmutable();
			C_2 = C_2.mul(h_i).getImmutable();
			}
		C_2 = C_2.powZn(s).getImmutable();
		ct.put("C_2", C_2);
		
		byte[] hash_val = H.hash((C_0.toString()+ C_1.toString()+ C_2.toString()).getBytes());
		Element c = pairing.getZr().newElementFromBytes(hash_val).getImmutable();
		Element C_3 = ((delta_1.powZn(c)).mul(delta_2.powZn(r)).mul(delta_3)).powZn(s).getImmutable();
		ct.put("C_3", C_3);
		
		long endTime = System.nanoTime();
//		System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");			
		return ct;
	}
	
	public Element decrypt(Threshold threshold, Map<String, Object> pk, Map<String, Object> sk_u, Map<String, Object> ct) {
		
		long startTime = System.nanoTime();
		
		Attribute[] setS = threshold.getsetS();
		int t = threshold.getTValue();
		
		Attribute[] W = (Attribute[]) ct.get("W");
		Element r = ((Element) ct.get("r")).duplicate().getImmutable();
		Element C_0 = ((Element) ct.get("C_0")).duplicate().getImmutable();
		Element C_1 = ((Element) ct.get("C_1")).duplicate().getImmutable();
		Element C_2 = ((Element) ct.get("C_2")).duplicate().getImmutable();
		Element C_3 = ((Element) ct.get("C_3")).duplicate().getImmutable();
	
		Attribute[] setS_W = (Attribute[]) CP_HABEwCS.addArrays(setS, W);
		
		Element g = ((Element) pk.get("g")).duplicate().getImmutable();
		Element g_2 = ((Element) pk.get("g_2")).duplicate().getImmutable();
		Element h_0 = ((Element) pk.get("h_0")).duplicate().getImmutable();
		Element delta_1 = ((Element) pk.get("delta_1")).duplicate().getImmutable();
		Element delta_2 = ((Element) pk.get("delta_2")).duplicate().getImmutable();
		Element delta_3 = ((Element) pk.get("delta_3")).duplicate().getImmutable();
		Hash H = (Hash) pk.get("H");
		
		Attribute[] overline_RA = (Attribute[]) sk_u.get("overline_RA");
		Attribute[] overline_RA_prime = Utils.intersection(setS, overline_RA);
		if(overline_RA_prime.length < t){
			System.out.println("policy matching fails!");
			return null;
		}
		
		byte[] hash_val = H.hash((C_0.toString()+ C_1.toString()+ C_2.toString()).getBytes());
		Element c = pairing.getZr().newElementFromBytes(hash_val).getImmutable();
		
		Element temp_one = h_0.duplicate().getImmutable();
		for(int i = 0; i < setS_W .length; i++){
			String attr = setS_W[i].toString();
			Element h_i = ((Element) pk.get("h_" + attr)).duplicate().getImmutable();
			temp_one = temp_one.mul(h_i).getImmutable();
			}
		
		Element left_upper_term = pairing.pairing(g, C_2).getImmutable();
		Element right_upper_term = pairing.pairing(C_1, temp_one).getImmutable();
		Element left_down_term = pairing.pairing(g, C_3).getImmutable();
		Element right_down_term = pairing.pairing(C_1, delta_3.mul(delta_1.powZn(c)).mul(delta_2.powZn(r))).getImmutable();
		if(!left_upper_term.equals(right_upper_term) || !left_down_term.equals(right_down_term)) {
			System.out.println("the ciphertext is invaild!");
			return null;
		}
		
		Attribute[] outter_set = (Attribute[]) CP_HABEwCS.addArrays(overline_RA_prime, W);
		
		Element D_1 = pairing.getG1().newOneElement().getImmutable();
		Element D_2 = pairing.getG1().newOneElement().getImmutable();
		
	    Element[] lagrangeCoeffi = Utils.lagrange(outter_set);
	    
		for(int i = 0; i < outter_set.length; i++) {
			String attr = outter_set[i].toString();
			
			Element temp_D_1 = pairing.getG1().newOneElement().getImmutable();
			Element temp_D_2 = pairing.getG1().newOneElement().getImmutable();
			for(int j = 0; j < setS_W.length; j++){
				String temp_attr = setS_W[j].toString();
				if(!temp_attr.equals(attr)) {
					Element c_i_j_overline = ((Element) sk_u.get("c_" + attr + "_" + temp_attr+ "_overline")).duplicate().getImmutable();
					temp_D_1 = temp_D_1.mul(c_i_j_overline).getImmutable();
				}
			}
			Element a_i_overline = ((Element) sk_u.get("a_" + attr + "_overline")).getImmutable().duplicate();
			Element b_i_overline = ((Element) sk_u.get("b_" + attr + "_overline")).getImmutable().duplicate();
			temp_D_1 = (temp_D_1.mul(a_i_overline)).powZn(lagrangeCoeffi[i]).getImmutable();
			temp_D_2 = (temp_D_2.mul(b_i_overline)).powZn(lagrangeCoeffi[i]).getImmutable();
			D_1 = D_1.mul(temp_D_1).getImmutable();
			D_2 = D_2.mul(temp_D_2).getImmutable();
		}
		Element res = C_0.mul(pairing.pairing(C_2, D_2)).div(pairing.pairing(C_1, D_1)).getImmutable();
		
		long endTime = System.nanoTime();
		System.out.println(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");	
		return res;
	}
	
	
	public static String toString(Map<String, Object> map){
		StringBuilder sb = new StringBuilder();
		sb.append(map.get("type")+ ":\n");
		sb.append("Components:{\n");
		Iterator<Entry<String, Object>> iterator = map.entrySet().iterator();
	    while(iterator.hasNext())
	    {
	     Map.Entry<String, Object> entry=(Entry<String, Object>) iterator.next();
	     if(!entry.getKey().equals("type") && !entry.getKey().equals("id_vector") && !entry.getKey().equals("set_s"))
	    	 sb.append(entry.getKey() + "---> " + entry.getValue()+ "\n");
	     else if(entry.getKey().equals("id_vector")) {
	    	 String[] ID = (String[]) entry.getValue();
	    	 sb.append(entry.getKey() + "---> ");
	    	 for(int i = 0; i < ID.length; i++)
	    		 sb.append(ID[i] + " ");
	    	 sb.append("\n");
	     }
	     else if(entry.getKey().equals("set_s")) {
	    	 Attribute[] set_s = (Attribute[]) entry.getValue();
	    	 sb.append(entry.getKey() + "---> ");
	    	 for(int i = 0; i < set_s.length; i++)
	    		 sb.append(set_s[i].getAttrName()+ ":" + set_s[i].getAttrValue() + " ");
	    	 sb.append("\n");
	     }
	  }
	    sb.append("}");
		return sb.toString();
	}
	

	public static Object[] addArrays(Object[] A, Object[] B) {
		Object[] joinedArray = (Object[]) Array.newInstance(A.getClass().getComponentType(), A.length + B.length);
		System.arraycopy(A, 0, joinedArray, 0, A.length);
		try {
			System.arraycopy(B, 0, joinedArray, A.length, B.length);
		} catch (ArrayStoreException ase) {
			//the type needs to be same.
			final Class<?> type1 = A.getClass().getComponentType();
			final Class<?> type2 = B.getClass().getComponentType();
			if (!type1.isAssignableFrom(type2)) {
				throw new IllegalArgumentException("Cannot store " + type2.getName() + " in an array of " + type1.getName());
			}
		throw ase; 
    }
    return joinedArray;
}
	
    public static boolean isSubSet(Attribute[] A, Attribute[] B){
    	List<Attribute> A_list = new ArrayList<>(Arrays.asList(A));
    	List<Attribute> B_list = new ArrayList<>(Arrays.asList(B));
    	return A_list.containsAll(B_list);
    }
       
	public static void main(String[] args) throws Exception {
		
		Attribute[] universe = new Attribute[3];
		universe[0] = new Attribute("school", "pku1");
		universe[1] = new Attribute("academy", "computer");
		universe[2] = new Attribute("id", "1701110xxx");

		
		CP_HABEwCS scheme = new CP_HABEwCS();
		
		Map<String, Object>[] res = scheme.setup(universe);
		Map<String, Object> pk = res[0];
		Map<String, Object> msk = res[1];
		System.out.println(KP_HABE_NMaCS.toString(pk) + "\n");
		System.out.println(KP_HABE_NMaCS.toString(msk) + "\n");
		
		Attribute[] RA = new Attribute[2];
		RA[0] = new Attribute("school", "pku1");
		RA[1] = new Attribute("academy", "computer");
//		RA[2] = new Attribute("id", "1701110xxx");
		Map<String, Object> sk_da = scheme.createDA(msk, pk, RA);
		System.out.println(KP_HABE_NMaCS.toString(sk_da) + "\n");
		
		Attribute[] overline_RA = new Attribute[2];
		overline_RA[0] = new Attribute("school", "pku1");
		overline_RA[1] = new Attribute("academy", "computer");
//		overline_RA[2] = new Attribute("id", "1701110xxx");
		Map<String, Object> sk_da_u = scheme.delegate(pk, sk_da, overline_RA);
		System.out.println(KP_HABE_NMaCS.toString(sk_da_u) + "\n");
		
		String message = "This a test!";
		Attribute[] set_S = new Attribute[1];
		set_S[0] = new Attribute("school", "pku1");
		Threshold threshold = new Threshold(set_S, 1);
		Map<String, Object> ct = scheme.encrypt(pk, message, threshold);
		System.out.println(KP_HABE_NMaCS.toString(ct) + "\n");

		Element m = scheme.decrypt(threshold, pk, sk_da_u, ct);
		System.out.println("m:" + m + "\n");


	}
}