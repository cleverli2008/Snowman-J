package abe;

/*
 * author: licong
 */

import it.unisa.dia.gas.jpbc.Element;
import utils.ISerializable;

import java.util.HashMap;
import java.util.Map;

import com.alibaba.fastjson.JSONObject;

public class Ciphertext implements ISerializable{
	
	private Attribute[] attributes;
	private Map<String, Element> components;
	private byte[] load; 
	
	public Ciphertext(){
		this.components = new HashMap<String, Element>();
	}

	
	public void setAttributes(Attribute[] attributes){
		this.attributes = attributes;
	}
	
	public Attribute[] getAttributes(){
		return attributes;
	}
	
	public Map<String, Element> getComponents() {
		return components;
	}
	
	public byte[] getLoad() {
		return load;
	}
	
	public void setLoad(byte[] load){
		this.load = load;
	}
	
	public static String attributesToString(Attribute[] attributes){
		
		String str="";
		for(int i=0; i<attributes.length; i++){
			if(i==0)
			str+=attributes[i].toString();
			else
			str+="_"+attributes[i].toString();
		}	
	   return str;
	}
	
	@Override   
	public String toJSONString() {
		JSONObject obj = new JSONObject();
		obj.put("attributes", attributesToString(this.attributes));
		obj.put("attrnum", this.attributes.length);
		for(Map.Entry<String, Element> entry : this.components.entrySet()){
			obj.put(entry.getKey(), entry.getValue().toBytes());
		}
		obj.put("load", load);
		return obj.toJSONString();
	}
	
	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb.append("Attributes:{\n");
		for(int i=0; i<attributes.length; i++)
			sb.append(attributes[i] + "\t");
		sb.append("}\n");
		sb.append("Components:{\n");
		for(Map.Entry<String, Element> element : getComponents().entrySet()){
			sb.append(element.getKey() + "----> " + element.getValue() + "\n");
		}
		sb.append("}");
		return sb.toString();
	}
}
