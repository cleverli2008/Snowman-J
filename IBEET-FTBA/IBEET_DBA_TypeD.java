package scheme;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import utils.Hash;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

/**
*  Created by cleverli on 2022.9.19
*  Modified by cleverli on 2024.1.23
**/

public class IBEET_DBA_TypeD {
	
	private Pairing pairing = PairingFactory.getPairing("scheme/d224.properties");
	public byte[] byte_e_gg = null;
	
	public List<Map<String, Object>> setup() {
		
		long startTime = System.nanoTime();
		
		// Pick hash functions
		Hash H_1 = new Hash("SHA-1");
		Hash H_2 = new Hash("SHA-1");
		Hash F_2 = new Hash("SHA-256");
		Hash F_3 = new Hash("SHA-256");
		
		// Generate the master key
		Element alpha = pairing.getZr().newRandomElement().getImmutable();
		
		Map<String, Object> masterKey = new HashMap<String, Object>();
		masterKey.put("type", "msk");
		masterKey.put("alpha", alpha);
		
		// Generate public parameters 
		
		//G1
		Element g = pairing.getG1().newRandomElement().getImmutable();
		Element g_1 = g.powZn(alpha).getImmutable();
		
		//G2
		Element g_2 = pairing.getG2().newRandomElement().getImmutable();
		Element h_0 = pairing.getG2().newRandomElement().getImmutable();
		Element h_1 = pairing.getG2().newRandomElement().getImmutable();
		Element h_2 = pairing.getG2().newRandomElement().getImmutable();
		Element h_3 = pairing.getG2().newRandomElement().getImmutable();
		
		Map<String, Object> publicKey = new HashMap<String, Object>();
		publicKey.put("type", "pk");
		
		publicKey.put("g", g);
		publicKey.put("g_1", g_1);
		
		publicKey.put("g_2", g_2);
		publicKey.put("h_0", h_0);
		publicKey.put("h_1", h_1);
		publicKey.put("h_2", h_2);
		publicKey.put("h_3", h_3);
		publicKey.put("H_1", H_1);
		publicKey.put("H_2", H_2);
		publicKey.put("F_2", F_2);
		publicKey.put("F_3", F_3);
	
		// Set the key array
		List<Map<String, Object>> res = new ArrayList<Map<String, Object>>();
		res.add(0, publicKey);
		res.add(1, masterKey);
		
		//Evaluate
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");			
		return res;
	}

	public Map<String, Object> keygen(Map<String, Object> pk, Map<String, Object> msk, String ID) {
		
		long startTime = System.nanoTime();
		
		if(pk == null || !(((String)pk.get("type")).equals("pk"))) {
			System.out.println("The input pk is error!");
			return null;
		}
		
		if(msk == null || !(((String)msk.get("type")).equals("msk"))) {
			System.out.println("The input msk is error!");
			return null;
		}
		
		if(ID == null || ID.trim().length() == 0) {
			System.out.println("The input ID is error!");
			return null;
		}
		
		Element alpha = ((Element)msk.get("alpha")).duplicate().getImmutable();
		Hash F_2 = ((Hash)pk.get("F_2"));
		Hash F_3 = ((Hash)pk.get("F_3"));
		
		//Use F_2 to hash ID
		byte[] byte_F_2_ID = F_2.hash(ID.getBytes());
		Element g_ID_2 = Utils.bytes2element(byte_F_2_ID, "G2").getImmutable();
		
		//Use F_3 to hash ID
		byte[] byte_F_3_ID = F_3.hash(ID.getBytes());
		Element g_ID_3 = Utils.bytes2element(byte_F_3_ID, "G2").getImmutable();
		
		//Compute F_2(ID) and F_3(ID)
        Element K_1 = g_ID_2.powZn(alpha).getImmutable();
        Element K_2 = g_ID_3.powZn(alpha).getImmutable();
        
        //Set the secret key
        Map<String, Object> sk = new HashMap<String, Object>();
		sk.put("type", "sk");
		sk.put("ID", ID);
		sk.put("K_1", K_1);
		sk.put("K_2", K_2);
		
		//Evaluate
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");		
		
		return sk;
	}

	public Map<String, Object> encrypt(Map<String, Object> pk, String ID, byte[] m, String[] T){
		
		long startTime = System.nanoTime();
		
		if(pk == null || !(((String)pk.get("type")).equals("pk"))) {
			System.out.println("The input pk is error!");
			return null;
		}
		
		if(ID == null || ID.trim().length() == 0) {
			System.out.println("The input ID is error!");
			return null;
		}
		
		if(m == null || m.length == 0) {
			System.out.println("The input message is error!");
			return null;
		}
		
		if(T == null || T.length == 0) {
			System.out.println("The input T is error!");
			return null;
		}
		
		//G2
		Element g = ((Element)pk.get("g")).duplicate().getImmutable();
		Element g_1 = ((Element)pk.get("g_1")).duplicate().getImmutable();
		
		//G1
		Element g_2 = ((Element)pk.get("g_2")).duplicate().getImmutable();
		Hash H_1 = ((Hash)pk.get("H_1"));
		Hash H_2 = ((Hash)pk.get("H_2"));
		Hash F_2 = ((Hash)pk.get("F_2"));
		Hash F_3 = ((Hash)pk.get("F_3"));
		
		Element r = pairing.getZr().newRandomElement().getImmutable();
		
		//Compute C_1
		Element C_1 = g.powZn(r).getImmutable();
		
		byte[] byte_F_2 = F_2.hash(ID.getBytes());
		Element F_2_ID = Utils.bytes2element(byte_F_2, "G2").getImmutable();

		Element e_gg_F_2 = pairing.pairing(g_1,F_2_ID.powZn(r)).getImmutable();
		byte[] byte_e_gg = H_1.hash(e_gg_F_2.toBytes());
		
		//make m be the standard length
		byte[] zero = null;
		try {
			zero = "0".getBytes("utf-8");
			zero = H_2.hash(zero);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		byte[] byte_m = Utils.byte_array_Xor(Utils.byte_array_Xor(zero, m),zero);
		
		//Compute C_2
		Element h_m_r = Utils.bytes2element(byte_m, "G2");
		h_m_r.powZn(r);
		byte[] C_2 = Utils.byte_array_Xor(byte_e_gg, h_m_r.toBytes());
		this.byte_e_gg = byte_e_gg;
		
		//Compute C_3
		Element C_3 = g_2.duplicate().getImmutable();
		Element h_0 = ((Element) pk.get("h_0")).duplicate().getImmutable(); 
		C_3 = C_3.mul(h_0.powZn(pairing.getZr().newElementFromBytes(ID.getBytes()))).getImmutable();
		
		for(int i = 0; i < T.length && i < 3; i++) {
			Element h_i = ((Element) pk.get("h_" + (i + 1) )).duplicate().getImmutable(); 
			C_3 = C_3.mul(h_i.powZn(pairing.getZr().newElementFromBytes(T[i].getBytes()))).getImmutable();
		}
		C_3 = C_3.powZn(r).getImmutable();
		
		byte[] byte_F_3 = F_3.hash(ID.getBytes());
		Element F_3_ID = Utils.bytes2element(byte_F_3, "G2").getImmutable();
		
		//Compute C_4
		Element e_gg_F_3 = pairing.pairing(g_1, F_3_ID.powZn(r)).getImmutable();
		String str_e_gg_F_3 = new String(e_gg_F_3.toBytes());
		String str_C_1 = new String (C_1.toBytes());
		String str_C_2 = new String (C_2);
		String str_C_3 = new String (C_3.toBytes());
		String str = str_e_gg_F_3+ str_C_1 + str_C_2 + str_C_3;
		for(int i=0; i < T.length; i++) {
			str += T[i];
		}
		
		byte[] hash_val = null;
		try {
			hash_val = H_2.hash(str.getBytes("utf-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] C_4 = Utils.byte_array_Xor(hash_val, m);
			
		//Set the ciphertext
		Map<String, Object> ct = new HashMap<String, Object>();
		ct.put("type", "ct");
		ct.put("ID", ID);
		ct.put("T", T);
		ct.put("C_1", C_1);
		ct.put("C_2", C_2);
		ct.put("C_3", C_3);
		ct.put("C_4", C_4);
		
		//Evaluate
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");
		
		return ct;
	}
	
	public byte[] decrypt(Map<String, Object> pk, Map<String, Object> sk, Map<String, Object> ct) {
		
		long startTime = System.nanoTime();
		
		if(pk == null || !(((String)pk.get("type")).equals("pk"))) {
			System.out.println("The input pk is error!");
			return null;
		}
		
		if(sk == null || !(((String)sk.get("type")).equals("sk"))) {
			System.out.println("The input sk is error!");
			return null;
		}
		
		if(ct == null || !(((String)ct.get("type")).equals("ct"))) {
			System.out.println("The input ct is error!");
			return null;
		}
		
		//Parse sk
		String ID = (String) sk.get("ID");
		Element K_1 = ((Element)sk.get("K_1")).duplicate().getImmutable();
		Element K_2 = ((Element)sk.get("K_2")).duplicate().getImmutable();
		
		//Parse ct
		String [] T = (String[])ct.get("T");
		Element C_1 = ((Element)ct.get("C_1")).duplicate().getImmutable();
		byte[] C_2 = (byte[])ct.get("C_2");
		Element C_3 = ((Element)ct.get("C_3")).duplicate().getImmutable();
		byte[] C_4 = (byte[])ct.get("C_4");	
		
		//Get pp
		Hash H_1 = ((Hash)pk.get("H_1"));
		Hash H_2 = ((Hash)pk.get("H_2"));
		Element g = ((Element)pk.get("g")).duplicate().getImmutable();
		
		//Judge
		String ID_prime = (String) ct.get("ID");
		if(!ID.equals(ID_prime)){
			System.out.println("Not matching!");
			return null;
		}
		
		Element e_gg_F_3 = pairing.pairing(C_1, K_2).getImmutable();
		
		//Compute m
		String str_e_gg_F_3 = new String(e_gg_F_3.toBytes());
		String str_C_1 = new String (C_1.toBytes());
		String str_C_2 = new String (C_2);
		String str_C_3 = new String (C_3.toBytes());
		String str = str_e_gg_F_3+ str_C_1 + str_C_2 + str_C_3;
		for(int i = 0; i < T.length; i++) {
			str += T[i];
		}
		
		byte[] hash_val = null;
		try {
			hash_val = H_2.hash(str.getBytes("utf-8"));
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		byte[] m = Utils.byte_array_Xor(C_4, hash_val);
				
		//Compute A
		Element e_gg_F_2 = pairing.pairing(C_1, K_1).getImmutable();
		byte[] byte_e_gg = H_1.hash(e_gg_F_2.toBytes());
		
		byte[] byte_A = Utils.byte_array_Xor(C_2, byte_e_gg);
		
		Element A = pairing.getG2().newElementFromBytes(byte_A).getImmutable();
		
		//Check equation 
		Element h_m = Utils.bytes2element(m, "G2");

		Element equ_left = pairing.pairing(C_1, h_m).getImmutable();
		Element equ_right = pairing.pairing(g, A).getImmutable();
		if(equ_left.equals(equ_right)){
			long endTime = System.nanoTime();
			System.out.println(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");
			return m;
		}
		else {
			System.out.println("The equation does not hold!");
			return null;
		}
	}
	
	public Map<String, Object> auth(Map<String, Object> pk, Map<String, Object> sk, String[] T, int type){
		
		long startTime = System.nanoTime();
		
		if(pk == null || !(((String)pk.get("type")).equals("pk"))) {
			System.out.println("The input pk is error!");
			return null;
		}
		
		if(sk == null || !(((String)sk.get("type")).equals("sk"))) {
			System.out.println("The input sk is error!");
			return null;
		}
		
		if(!(type==1 || type==2 || type ==3)) {
			System.out.println("The input type is error!");
			return null;
		}
		
		//Obtain pp
		Element h_0 = ((Element)pk.get("h_0")).duplicate().getImmutable();
		Element h_1 = ((Element)pk.get("h_1")).duplicate().getImmutable();
		Element h_2 = ((Element)pk.get("h_2")).duplicate().getImmutable();
		Element h_3 = ((Element)pk.get("h_3")).duplicate().getImmutable();
		Element g = ((Element)pk.get("g")).duplicate().getImmutable();
		Element g_2 = ((Element)pk.get("g_2")).duplicate().getImmutable();
		
		//Obtain sk
		Element K_1 = ((Element)sk.get("K_1")).duplicate().getImmutable();
		String ID = ((String)sk.get("ID"));
		
		Element pre_compute_item = (h_0.powZn(pairing.getZr().newElementFromBytes(ID.getBytes()))).mul(h_1.powZn(pairing.getZr().newElementFromBytes(T[0].getBytes()))).mul(g_2);
		Element T_0 = null;
		Element T_1 = null;
		Element T_2 = null;
		Element T_3 = null;
		
		Element r = pairing.getZr().newRandomElement().getImmutable();
		
		//Three types
		if(type == 1) {
			T_0 = K_1.mul(pre_compute_item.powZn(r)).getImmutable();
			T_1 = g.powZn(r).getImmutable();
			T_2 = h_2.powZn(r).getImmutable();
			T_3 = h_3.powZn(r).getImmutable();
		}
		else if(type == 2) {
			T_0 = K_1.mul((pre_compute_item.mul(h_2.powZn(pairing.getZr().newElementFromBytes(T[1].getBytes())))).powZn(r)).getImmutable();
			T_1 = g.powZn(r).getImmutable();
			T_2 = h_2.powZn(r).getImmutable();
			T_3 = h_3.powZn(r).getImmutable();
		}
		else {
			T_0 = K_1.mul((pre_compute_item.mul(h_2.powZn(pairing.getZr().newElementFromBytes(T[1].getBytes()))).mul(h_3.powZn(pairing.getZr().newElementFromBytes(T[2].getBytes())))).powZn(r)).getImmutable();
			T_1 = g.powZn(r).getImmutable();
			T_2 = h_2.powZn(r).getImmutable();
			T_3 = h_3.powZn(r).getImmutable();
		}
		
		//Set trapdoor
		Map<String, Object> td = new HashMap<String, Object>();
		if(T_0!=null && T_1 != null && T_2 != null && T_3 != null) {
		td.put("type", "td");
		td.put("td_type", type);
		td.put("T", T);
		td.put("T_0", T_0);
		td.put("T_1", T_1);
		td.put("T_2", T_2);
		td.put("T_3", T_3);
		
		//Evaluate
		long endTime = System.nanoTime();
		System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");		
		return td;
		}
		else {
			System.out.println("There has an fault in the trapdoor generation process!");
			return null;
		}
		
	}
	
	public Object test(Map<String, Object> pk, Map<String, Object> ct_1, Map<String, Object> td_1, Map<String, Object> ct_2, Map<String, Object> td_2){
		
		long startTime = System.nanoTime();
	
		if(ct_1== null || !(((String)ct_1.get("type")).equals("ct")) || ct_2 == null || !(((String)ct_2.get("type")).equals("ct"))) {
			System.out.println("The input ct_1 or ct_2 is error!");
			return null;
		}
		
		//obtain C_1_1
		Element C_1_1 = ((Element)ct_1.get("C_1")).duplicate().getImmutable();
		
		//obtain C_1_2
		Element C_1_2 = ((Element)ct_2.get("C_1")).duplicate().getImmutable();
		
		Element delta_1 = IBEET_DBA_TypeD.compute(pk, ct_1, td_1, pairing);
		Element delta_2 = IBEET_DBA_TypeD.compute(pk, ct_2, td_2, pairing);
		
		Element equ_left = pairing.pairing(C_1_2, delta_1).getImmutable();
		Element equ_right = pairing.pairing(C_1_1, delta_2).getImmutable();
		
		if(equ_left.equals(equ_right)){
			long endTime = System.nanoTime();
			System.out.print(String.format("%.2f", (float)((endTime - startTime) / 1_000_000.0000))+ " ");
			return true;
		}
		else {
			return false;
		}		
	}
	
	//Compute C_x \xor \cita type
	private static Element compute(Map<String, Object> pk, Map<String, Object> ct, Map<String, Object> td, Pairing pairing) {
		
        //obtain td
		String[] T_prime = (String[])td.get("T");
		int type = (int)td.get("td_type");
		Element T_0 = ((Element)td.get("T_0")).duplicate().getImmutable();
		Element T_1 = ((Element)td.get("T_1")).duplicate().getImmutable();
		Element T_2 = ((Element)td.get("T_2")).duplicate().getImmutable();
		Element T_3 = ((Element)td.get("T_3")).duplicate().getImmutable();
				
	    //obtain ct
		String[] T = (String[])ct.get("T");
		Element C_1 = ((Element)ct.get("C_1")).duplicate().getImmutable();
		byte[] C_2 = (byte[])ct.get("C_2");
		Element C_3 = ((Element)ct.get("C_3")).duplicate().getImmutable();
		
		//obtain pp
		Hash H_1 = (Hash)pk.get("H_1");
		
		if(!Utils.prefix(T, T_prime))
		{
			System.out.println("Not matching!");
			return null;
		}
		
		Element[] T_elem = new Element[T.length];
		
		for(int i = 0; i < T_elem.length; i++) {
			T_elem[i] = pairing.getZr().newElementFromBytes(T[i].getBytes()).getImmutable();
		}
		
		Element sum = null;
		if(type == 1){
			sum = (pairing.pairing(C_1,T_0.mul(T_2.powZn(T_elem[1]).mul(T_3.powZn(T_elem[2]))))).div(pairing.pairing(T_1,C_3)).getImmutable();
		}
		else if (type == 2){
			sum = (pairing.pairing(C_1,T_0.mul(T_3.powZn(T_elem[2])))).div(pairing.pairing(T_1,C_3)).getImmutable();
		}
		else{
			sum = (pairing.pairing(C_1,T_0)).div(pairing.pairing(T_1,C_3)).getImmutable();
		}
		
		byte[] cita = H_1.hash(sum.toBytes());
		byte[] delta = Utils.byte_array_Xor(C_2, cita);
		
		//Element res = pairing.getG1().newElementFromBytes(delta).getImmutable();
		Element res = Utils.bytes2element(delta, "G2").getImmutable();
		
		return res;
	}

	//Test function
	public void function_test(IBEET_DBA_TypeD scheme) {
		 
		 List<Map<String, Object>> keys = scheme.setup();
		 Map<String, Object> pk = keys.get(0);
		 Map<String, Object> msk = keys.get(1);
		 
		 System.out.println("pp:" + pk);
		 System.out.println("msk:" + msk);
	
		 String ID = "1701110680";
		 Map<String, Object> sk = scheme.keygen(pk, msk, ID);
		 System.out.println("sk:" + sk);
		 
		 String[] T = {"2021","9","17"};
		 int type = 3;
		 Map<String, Object> td = scheme.auth(pk, sk, T, type);
		 
	 
		byte[] m = null;
		 
		try {
			m = "This is a test!".getBytes("utf-8");
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
	
		 byte[] m_1 = null;
		 try {
			m_1 = "Keep on moving".getBytes("utf-8");
		} catch (UnsupportedEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}
		
		 Map<String, Object> ct = scheme.encrypt(pk, ID, m, T);
		 System.out.println("ct" + ct);
		 
		 byte[] res = scheme.decrypt(pk, sk, ct);
		 String str_res = null;
		try {
			str_res = new String(res, "utf-8");
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		 System.out.println("res:" + str_res);
		 
		 String ID_1 = "1701110000";
		 Map<String, Object> sk_1 = scheme.keygen(pk, msk, ID_1);
		 
		 String[] T_1_prime = {"2021"};
		 String[] T_1 = {"2021","9","16"};
		 int type_1 = 1;
		 
		 Map<String, Object> td_1 = scheme.auth(pk, sk_1, T_1_prime, type_1);
		 
		 Map<String, Object> ct_1 = scheme.encrypt(pk, ID_1, m, T_1);
		
		 Boolean flag = (Boolean) scheme.test(pk, ct, td, ct_1, td_1);
		 System.out.print("The result of test is: "+ flag); 
	}
	
}

