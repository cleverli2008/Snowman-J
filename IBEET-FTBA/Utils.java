package scheme;

import java.io.FileWriter;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

public class Utils {
	
//	private static Pairing pairing = PairingFactory.getPairing("scheme/a.properties");
	private static Pairing pairing = PairingFactory.getPairing("scheme/d224.properties");
	
	public static void maptofile(Map input, String url) {

		String line = System.getProperty("line.separator");

		StringBuffer str = new StringBuffer();

		Set set = input.entrySet();

		Iterator iter = set.iterator();

		while (iter.hasNext()) {
			Map.Entry entry = (Map.Entry) iter.next();
			str.append(entry.getKey() + " : " + entry.getValue()).append(line);
		}
		Utils.output(str.toString(), url);
	}

	public static void elementarraytofile(Element[] input, String[] inputName, String url) {

		String line = System.getProperty("line.separator");

		StringBuffer str = new StringBuffer();

		for (int i = 0; i < input.length; i++) {
			str.append(inputName[i] + " : " + input[i]).append(line);
		}

		Utils.output(str.toString(), url);
	}

	public static void elementtofile(Element input, String inputName, String url) {

		String line = System.getProperty("line.separator");

		String str = inputName + " : " + input;

		Utils.output(str, url);
	}

	public static void output(String outputString, String url) {

		try {
			String line = System.getProperty("line.separator");

			StringBuffer str = new StringBuffer();

			FileWriter fw = new FileWriter(url, true);

			fw.write(outputString);
			fw.close();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	 //Xor
		public static byte[] byte_array_Xor(byte[] b1, byte[] b2) {
	      
	        byte longbytes[],shortbytes[];
	        if(b1.length>=b2.length){
	            longbytes = b1;
	            shortbytes = b2;
	        }else{
	            longbytes = b2;
	            shortbytes = b1;
	        }
	        byte xorstr[] = new byte[longbytes.length];
	        int i = 0;
	        for (; i < shortbytes.length; i++) {
	            xorstr[i] = (byte)(shortbytes[i]^longbytes[i]);
	        }
	        for (;i<longbytes.length;i++){
	            xorstr[i] = longbytes[i];
	        }
	        return xorstr;
	    }

       public static byte[] addBytes(byte[] front, byte[] after) {
    	   byte[] temp = new byte[front.length+after.length];
    	   System.arraycopy(front, 0, temp, 0, front.length);
    	   System.arraycopy(after, 0, temp, front.length, after.length);
    	   return temp;
       }
       
   	public static Element bytes2element(byte[] bytes, String type){
   		
   		Element elem = null;
   		
   		if(type.equals("G1")){
   			elem = pairing.getG1().newZeroElement();
   		}
   		else if(type.equals("G2")){
   			elem = pairing.getG2().newZeroElement();	
   		}
   		else if(type.equals("Zr")){
   			elem = pairing.getZr().newZeroElement();	
   		}
   		else if(type.equals("GT")){
   			elem = pairing.getGT().newZeroElement();
   		}
   		else
   			return elem;
   		
   		elem.setFromHash(bytes, 0, bytes.length);
   		return elem;
	}
   	
   	public static Map<String,Object> object2map(Object obj){
   		Map<String,Object> map = new HashMap<>();
   		if(obj == null) {
   			return map;
   		}
   		Class<? extends Object> cla = obj.getClass();
   		Field[] fields = cla.getDeclaredFields();
   		try {
   			for(Field field: fields) {
   				//field.setAccessible(true);
   				map.put(field.getName(), field.get(obj));
   			}
   		}catch (Exception e){
   			e.printStackTrace();
   		}
   		return map;
   	}

   	public static byte[][] byteSpliter(byte[] bt1, int bt2_length) {

		int difference = bt1.length - bt2_length;
		byte[] res_1 = new byte[difference];
		byte[] res_2 = new byte[bt2_length];
		System.arraycopy(bt1, 0, res_1, 0, difference);
		System.arraycopy(bt1, difference, res_2, 0, bt2_length);

		byte[][] res = new byte[2][];
		res[0] = res_1;
		res[1] = res_2;
		return res;
	}
 
  //Prefix
    public static boolean prefix(String[] vector_1, String[] vector_2) {
 	   int length = vector_1.length < vector_2.length?  vector_1.length: vector_2.length;
 	   for(int i = 0; i < length; i++){
 		   if(vector_1[i] != vector_2[i]){
 			   return false;
 		   }
 	   }
      return true;
    }
    
    public static boolean wildPrefix(String[] vector, String[] wildVector) {
    	
       if(vector.length != wildVector.length){
    	   return false;
       }   
  	   for(int i = 0; i < vector.length; i++){
  		   if(!(vector[i] == wildVector[i] || wildVector[i].equals("*"))){
  			   return false;
  		   }
  	   }
       return true;
     }

    public static ArrayList<Integer> getIndexofWildcards(int length, String[] wildVector){
    	
    	if(length > wildVector.length)
    		return null;
    	ArrayList<Integer> set = new ArrayList<Integer>();
    	 for(int i = 0; i < length; i++){
    		   if(wildVector[i].equals("*")){
    			   set.add(i);
    		   }
    	   }
    	return set;
    }

}
