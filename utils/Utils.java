package utils;

/*
 * author: licong
 */

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import abe.Attribute;


public class Utils {
	public static char SPACE = ' ';
	//private static Pairing pairing = PairingManager.getDefaultPairing();
	private static Pairing pairing = PairingFactory.getPairing("schemes/a.properties");
	
	/**
	 * format the string. i.e. remove redundant space
	 * @param s
	 * @return
	 */
	
	public static Element[] shamirSS(Attribute[] set_s, int t, Element s){

		Element[] shares = new Element[set_s.length];
		Element[] a = new Element[t];
		a[0] = s.duplicate().getImmutable();
		
		for(int i = 1; i < t; i++) {
			a[i] = pairing.getZr().newRandomElement().getImmutable();
		}
		
		for(int i = 0; i < set_s.length; i++) {
			Element val_i = pairing.getZr().newElementFromBytes(set_s[i].getAttrValue().getBytes()).getImmutable();
			Element temp = pairing.getZr().newZeroElement().getImmutable();
		
			for(int j = 0; j <= t-1; j ++) {
				if(j == 0) 
					temp = temp.add(a[0]).getImmutable();
				else {
				Element exp = pairing.getZr().newElement((int) j).getImmutable();
				temp = temp.add(a[j].mul(val_i.powZn(exp))).getImmutable();
				}
			}
			shares[i] = temp.duplicate().getImmutable();
		}
		
	  return shares;
	}
	
	
	public static Element[] lagrange(Attribute[] set_s) {
		
        Element[] lagrangeCoeffi = new Element[set_s.length];
        Element[] values = new Element[set_s.length];
        
        for(int i = 0; i < set_s.length; i++) {
        	values[i] = pairing.getZr().newElementFromBytes(set_s[i].getAttrValue().getBytes()).getImmutable();
        }
        
        for(int i = 0; i < set_s.length; i++) {
        	Element temp = pairing.getZr().newOneElement().getImmutable();
        	Element x_i = values[i].duplicate().getImmutable();
			for (int j = 0; j < set_s.length; j++) {
				if(j!=i) 
				temp = temp.mul((values[j].negate()).div(x_i.add(values[j].negate()))).getImmutable();
			}
			lagrangeCoeffi[i] = temp.duplicate().getImmutable();

        }
		return lagrangeCoeffi;
	}
	
	 public static Attribute[] intersection(Attribute[] m, Attribute[] n)
	    {
	        List<Attribute> rs = new ArrayList<Attribute>();

	        
	        Set<Attribute> set = new HashSet<Attribute>(Arrays.asList(m.length > n.length ? m : n));

	        for (Attribute i : m.length > n.length ? n : m)
	        {
	            if (set.contains(i))
	            {
	                rs.add(i);
	            }
	        }

	        Attribute[] arr = {};
	        return rs.toArray(arr);
	    }
	
	
	public static String format(String s){
		return s.trim().replaceAll("\\s+", SPACE+"");
	}
	
	public static boolean isEmptyString(String s){
		return s == null ? true : s.equals("") ? true : false; 
	}
	
	public static Element[] multiple(int[][] matrix, Element[] y){
		if(matrix == null || y == null)
			return null;
		Element[] res = new Element[matrix.length];
		for(int i=0; i<matrix.length; i++){
			res[i] = multiple(matrix[i], y);
		}
		return res;
	}
	
	private static Element multiple(int[] array, Element[] y){
		if(array == null || y == null || array.length != y.length)
			return null;
		Element res = pairing.getZr().newZeroElement();
		for(int i=0; i<array.length; i++){
			res.add(y[i].mul(array[i])).getImmutable();
		}
		return res;
	}
	
	public static <T> void printArray(T[] array){
		System.out.println("-------------array begin-------------");
		for(int i=0; i<array.length; i++){
			System.out.println(array[i]);
		}
		System.out.println("-------------array end-------------");
	}
	
	public static Element innerProduct(Element[] a, Element[] b){
		if(a == null || b == null || a.length == 0 || b.length == 0 || a.length != b.length){
			return null;
		}
		
		Element res = pairing.getZr().newZeroElement();
		for(int i=0; i<a.length; i++){
			res.add(a[i].duplicate().mul(b[i]));
		}
		return res;
	}
	
		
	public static void printMatrix(int[][] m){
		
		if(m == null)
			return;
		for(int i=0; i<m.length; i++){
			for(int j=0; j<m[i].length; j++){
				System.out.print(m[i][j] + "\t");
			}
			System.out.println();
		}
	}
	
	public static Map<Integer, Integer> attributesMatching(Attribute[] attributes, Map<Integer, String> rho){
		
	    Map<Integer, Integer> setI= new HashMap<Integer,Integer>();
				
		for (int i = 0; i < attributes.length; i++) {
			for (Map.Entry<Integer, String> entry : rho.entrySet()) {
				if (entry.getValue().equals(attributes[i].toString())) {
					setI.put(entry.getKey(),i);
				}
			}
		}
		
		return setI;
	}
	
	public static Element[] computeOmega(int[][] matrix,Map<Integer, Integer> setI){
		
		int cols = matrix[0].length;
		int[][] Mi = new int[setI.size()][cols];
		
		int k=0;
		for(Entry<Integer, Integer> entry : setI.entrySet()){
			   System.arraycopy(matrix[entry.getKey()], 0, Mi[k], 0, cols);
		       k++;
		}
		if (Mi.length==0||Mi[0].length==0){
//			System.out.println("Secret key can not satisfy the policy in the ciphertext!");
//			System.out.println("Decryption unsuccessfully!");
			return null;	
		}
		Element[][] Mi_ele = new Element[Mi.length][Mi[0].length];
//		BigInteger order=pairing.getZr().getOrder();
		for (int i = 0; i < Mi_ele.length; i++) {
			for(int j = 0; j < Mi_ele[0].length; j++){
			Mi_ele[i][j] = pairing.getZr().newElement((int) Mi[i][j]).getImmutable();
		  }
		}
		Element[][] Minv=Utils.inverse(Mi_ele);
        Solve solve =new Solve(Minv,Minv.length);
		Element[] solution = solve.equationSolve();
		if (solution == null) {
//			System.out.println("Secret key can not satisfy the policy in the ciphertext!");
//			System.out.println("Decryption unsuccessfully!");
			return null;
		}
		return solution;
	}
	
	public static Attribute[] computeNS(Attribute[] set_s, Map<Integer, String> rho) {
		
		Map<String,String> map_set_s = new HashMap<String,String>();
		for(int i = 0 ; i < set_s.length; i++) {
			map_set_s.put(set_s[i].getAttrName(), set_s[i].getAttrValue());
		} 
	
		List<Attribute> set_NS_list = new ArrayList<Attribute>(Arrays.asList(set_s));
		
		for (Entry<Integer, String> entry : rho.entrySet()) {
			String attr = entry.getValue();
			String[] tempArray  = Utils.splitAttribute(attr, ":");
			String attr_val = tempArray[1];
			String attr_name = tempArray[0];
			if(attr_val.charAt(0) =='-'){
				String attr_val_un = attr_val.substring(1);
				if(!(map_set_s.containsValue(attr_val_un) && map_set_s.containsKey(attr_name))){
					set_NS_list.add(new Attribute(attr_name, attr_val));
				}
			}
		}
		Attribute[] set_NS= set_NS_list.toArray(new Attribute[set_NS_list.size()]);
		return set_NS;
	}
	
	public static String[] splitAttribute(String attr, String symbol) {     
		String[] strs=attr.split(symbol);
		return strs;
    }
	
	public static Element[][] inverse(Element[][] M){
		
		if(M.length==0||M[0].length==0){
			System.out.println("The matrix is illegal!");
			return null;
		}
		Element[][] Minv= new Element[M[0].length][M.length];
		
		for (int i = 0; i < M.length; i++) {
			for(int j = 0; j < M[0].length; j++){
			    Minv[j][i]=M[i][j];
		  }  
		}
		
		return Minv;
	}
	
}
