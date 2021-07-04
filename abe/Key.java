package abe;

/*
 * author: licong
 */

import it.unisa.dia.gas.jpbc.Element;
import utils.ISerializable;

import java.util.HashMap;
import java.util.Map;
import com.alibaba.fastjson.JSONObject;

public class Key implements ISerializable {
	
	public static enum Type{PUBLIC, MASTER, SECRET, TRANSFER, AUTHORITY}
	protected Type type;
	protected Map<String, Element> components;
	
	public Key(){
		this.components = new HashMap<String, Element>();
	}
	
	public Key(Type type){
		this(); 
		this.type = type;
	}

	public Type getType() {
		return type;
	}

	public void setType(Type type) {
		this.type = type;
	}

	public Map<String, Element> getComponents() {
		return components;
	}

	@Override   
	public String toJSONString() {
		JSONObject obj = new JSONObject();
		obj.put("type", type);
		
		for(Map.Entry<String, Element> entry : this.components.entrySet()){
			obj.put(entry.getKey(), entry.getValue().toBytes());
		}

		return obj.toJSONString();
	}

	public String toString(){
		StringBuilder sb = new StringBuilder();
		sb.append("Type:" + getType() + "\n");
		sb.append("Components:{\n");
		for(Map.Entry<String, Element> element : getComponents().entrySet()){
			sb.append(element.getKey() + "---> " + element.getValue() + "\n");
		}
		sb.append("}");
		return sb.toString();
	}
}
