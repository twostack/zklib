// Code generated by gobind. DO NOT EDIT.

// Java class zklib.ProofObj is a proxy for talking to a Go program.
//
//   autogenerated by gobind -lang=java zklib
package zklib;

import go.Seq;

/**
 * Proof object to encapsulate the behaviour of
doing setup just once, and then repeatedly
constructing and verifying proofs and
 */
public final class ProofObj implements Seq.Proxy {
	static { Zklib.touch(); }
	
	private final int refnum;
	
	@Override public final int incRefnum() {
	      Seq.incGoRef(refnum, this);
	      return refnum;
	}
	
	ProofObj(int refnum) { this.refnum = refnum; Seq.trackGoRef(refnum, this); }
	
	public ProofObj() { this.refnum = __New(); Seq.trackGoRef(refnum, this); }
	
	private static native int __New();
	
	@Override public boolean equals(Object o) {
		if (o == null || !(o instanceof ProofObj)) {
		    return false;
		}
		ProofObj that = (ProofObj)o;
		return true;
	}
	
	@Override public int hashCode() {
	    return java.util.Arrays.hashCode(new Object[] {});
	}
	
	@Override public String toString() {
		StringBuilder b = new StringBuilder();
		b.append("ProofObj").append("{");
		return b.append("}").toString();
	}
}

