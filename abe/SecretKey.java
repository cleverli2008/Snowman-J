package abe;

/*
 * author: licong
 */

import it.unisa.dia.gas.jpbc.Element;
import java.util.Map;
import com.alibaba.fastjson.JSONObject;

public class SecretKey extends Key {

	private Policy policy;
	private int[][] matrix;
	private Map<Integer, String> rho;

	public SecretKey() {
		super(Type.SECRET);
	}

	public Policy getPolicy() {
		return policy;
	}

	public void setPolicy(Policy policy) {
		this.policy = policy;
	}

	public void setMatirx(int[][] matrix) {
		this.matrix = matrix;
	}

	public int[][] getMatirx() {
		return matrix;
	}

	public void setRho(Map<Integer, String> rho) {
		this.rho = rho;
	}

	public Map<Integer, String> getRho() {
		return rho;
	}

	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("policy:" + policy + "\n");
		sb.append("Components:{\n");
		for (Map.Entry<String, Element> element : getComponents().entrySet()) {
			sb.append(element.getKey() + "--->" + element.getValue() + "\n");
		}
		sb.append("}");
		return sb.toString();
	}

	@Override
	public String toJSONString() {
		JSONObject obj = new JSONObject();
		obj.put("type", type);
		obj.put("policy", policy.toString());
		for (Map.Entry<String, Element> entry : this.components.entrySet()) {
			obj.put(entry.getKey(), entry.getValue().toBytes());
		}
		return obj.toJSONString();
	}
}
