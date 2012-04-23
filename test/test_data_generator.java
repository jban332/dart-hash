/*
 Copyright 2012 Jban332 <jban332@gmail.com>.
 
 Permission is hereby granted, free of charge, to any person obtaining
 a copy of this software and associated documentation files (the
 "Software"), to deal in the Software without restriction, including
 without limitation the rights to use, copy, modify, merge, publish,
 distribute, sublicense, and/or sell copies of the Software, and to
 permit persons to whom the Software is furnished to do so, subject to
 the following conditions:
 
 The above copyright notice and this permission notice shall be
 included in all copies or substantial portions of the Software.
 
 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.Charset;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;

class test_data_generator {
    static String dir;
	static final Charset UTF8 = Charset.forName("UTF-8");
	static String toHex(byte[] bytes) {
		char[] chars = new char[bytes.length*2];
		final String VALUES = "0123456789abcdef";
		for (int i=0;i<bytes.length;i++) {
			int b = bytes[i];
            if (b<0) b = 256+b;
			chars[i*2] = VALUES.charAt(b>>4);
			chars[i*2+1] = VALUES.charAt(b%16);
		}
		return new String(chars);
	}
	
	public static void main(String[] args) {
        dir = args[0];
		Object[][] algorithms;
		algorithms = new Object[][] {
				new Object[] {"sha1", "SHA-1"},
				new Object[] {"sha2-224", "SHA-224"},
				new Object[] {"sha2-256", "SHA-256"},
				new Object[] {"sha2-384", "SHA-384"},
				new Object[] {"sha2-512", "SHA-512"}
		};
		PrintWriter pw;
		try {
			pw = new PrintWriter(new FileWriter(new File(dir+"/message_digest_data.txt")));
		} catch (IOException e) {
			throw new Error(e);
		}
        try {
            for (int a=0; a<algorithms.length; a++) {
                String name = (String)algorithms[a][0];
                MessageDigest md;
                try {
                    md = MessageDigest.getInstance((String)algorithms[a][1]);
                }
                catch (NoSuchAlgorithmException e) {
                    System.out.println("Skipping algorithm '"+name+"' because it's not available: "+e.toString());
                    continue;
                }
                System.out.println("Generating test data for algorithm '"+  name+"'.");
                pw.append("#Testing "+name+"\n");
                StringBuffer text = new StringBuffer();
                for (int l=0; l<257; l++) {
                    byte[] input = text.toString().getBytes(UTF8);
                    byte[] digest = md.digest(input);
                    pw.append(name);
                    pw.append(" a ");
                    pw.append(String.valueOf(text.length()));
                    pw.append(" ");
                    pw.append(toHex(digest));
                    pw.append("\n");
                    
                    // Increment text length
                    text.append('a');
                }
            }
        }
        finally {
            pw.flush();
        }
	}
}