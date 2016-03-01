// Author: A0145381H

import java.io.File;
import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.FileNotFoundException;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.PublicKey;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

/************************************************
  * This skeleton program is prepared for weak  *
  * and average students.                       *
  * If you are very strong in programming. DIY! *
  * Feel free to modify this program.           *
  ***********************************************/

// Amy knows Bryan's public key
// Amy sends Bryan session (AES) key
// Amy receives messages from Bryan, decrypts and saves them to file

class Amy {  // Amy is a TCP client
    
    String BryanIP;  // ip address of Bryan
    int BryanPort;   // port Bryan listens to
    Socket connectionSkt;  // socket used to talk to Bryan
    private ObjectOutputStream toBryan;   // to send session key to Bryan
    private ObjectInputStream fromBryan;  // to read encrypted messages from Bryan
    private Crypto crypto;        // object for encryption and decryption
    // file to store received and decrypted messages
    public static final String MESSAGE_FILE = "msgs.txt";
    
    public static void main(String[] args) {
        
        // Check if the number of command line argument is 2
        if (args.length != 2) {
            System.err.println("Usage: java Amy BryanIP BryanPort");
            System.exit(1);
        }
        
        new Amy(args[0], args[1]);
    }
    
    // Constructor
    public Amy(String ipStr, String portStr) {
        
        this.crypto = new Crypto();
        int port = Integer.parseInt(portStr);
        try {
			connectionSkt = new Socket(ipStr, port);
		} catch (IOException e) {
            System.out.println("Error creating connection socket");
            System.exit(1);
		}
        

        try {
            this.toBryan = new ObjectOutputStream(this.connectionSkt.getOutputStream());
            this.fromBryan = new ObjectInputStream(this.connectionSkt.getInputStream());
        } catch (IOException ioe) {
            System.out.println("Error: cannot get input/output streams");
            System.exit(1);
        }
        
        getPublicKey();
        // Send session key to Bryan
        sendSessionKey();
        
        // Receive encrypted messages from Bryan,
        // decrypt and save them to file
        receiveMessages();
    }
    
    private void getPublicKey() {
    	try {
			PublicKey pubKey = (PublicKey)this.fromBryan.readObject();
			byte[] sig = (byte[])this.fromBryan.readObject();
			MessageDigest md5 = MessageDigest.getInstance("MD5");
			md5.update("bryan".getBytes());
			md5.update(pubKey.getEncoded());
			byte[] actDigest = md5.digest();
			byte[] expDigest = this.crypto.decryptSig(sig);
			if(!MessageDigest.isEqual(actDigest, expDigest)){
				System.out.println("Error:MD5 signature does not match");
				System.exit(1);
			}
			else{
				this.crypto.setPublicKey(pubKey);
			}
		} catch (ClassNotFoundException | IOException e) {
			e.printStackTrace();
			System.exit(1);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(1);
		}
		
	}

	// Send session key to Bryan
    public void sendSessionKey() {
        try {
			this.toBryan.writeObject(crypto.getSessionKey());
		} catch (IOException e) {
			e.printStackTrace();
            System.exit(1);
		}
    }
    
    // Receive messages one by one from Bryan, decrypt and write to file
    public void receiveMessages() {
        String FILE_NAME = "msgs.txt";
        try {
			PrintWriter toFile = new PrintWriter(FILE_NAME);
			for(int i = 0; i < 10; i++){
				toFile.println(crypto.decryptMsg((SealedObject)this.fromBryan.readObject()));
			}
			toFile.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
			System.exit(1);
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			System.exit(1);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}
    }
    
    /*****************/
    /** inner class **/
    /*****************/
    class Crypto {
        
        // Bryan's public key, to be read from file
        private PublicKey pubKeyOfBerisign;
        private PublicKey pubKey;
        // Amy generates a new session key for each communication session
        private SecretKey sessionKey;
        // File that contains Berisign' public key
        public static final String PUBLIC_KEY_FILE = "berisign.pub";
        
        // Constructor
        public Crypto() {
            // Read Bryan's public key from file
            readPublicKey();
            // Generate session key dynamically
            initSessionKey();
        }
        
        public byte[] decryptSig(byte[] sig) {

        	try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, pubKeyOfBerisign);
                cipher.update(sig);
                return cipher.doFinal();
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (InvalidKeyException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (BadPaddingException e) {
				e.printStackTrace();
                System.exit(1);	
			}
			return null;
		}

		public void setPublicKey(PublicKey key) {
			pubKey = key;
		}
        
        

		// Read Bryan's public key from file
        public void readPublicKey() {
            // key is stored as an object and need to be read using ObjectInputStream.
            // See how Berisign read his private key as an example.
        	try {
                ObjectInputStream ois = 
                    new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
                this.pubKeyOfBerisign = (PublicKey)ois.readObject();
                ois.close();
            } catch (IOException oie) {
                System.out.println("Error reading private key from file");
                System.exit(1);
            } catch (ClassNotFoundException cnfe) {
                System.out.println("Error: cannot typecast to class PrivateKey");
                System.exit(1);
            }
            
            System.out.println("Private key read from file " + PUBLIC_KEY_FILE);
        }
        
        // Generate a session key
        public void initSessionKey() {
            // suggested AES key length is 128 bits
        	KeyGenerator generator;
        	try {
				generator = KeyGenerator.getInstance("AES");
	        	sessionKey = generator.generateKey();
			} catch (NoSuchAlgorithmException e) {
                System.out.println("Error: cannot create a generator");
                System.exit(1);	
			}
        }
        
        // Seal session key with RSA public key in a SealedObject and return
        public SealedObject getSessionKey() {
            
            // Amy must use the same RSA key/transformation as Bryan specified
            try {
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, this.pubKey);
			    byte[] keyBytes = sessionKey.getEncoded();
                SealedObject sessionKeyObj = new SealedObject(keyBytes, cipher);
                return sessionKeyObj;
			} catch (InvalidKeyException e) {
				e.printStackTrace();
                System.exit(1);	
				
			} catch (NoSuchAlgorithmException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (NoSuchPaddingException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (IOException e) {
				e.printStackTrace();
                System.exit(1);	
			}
            return null;
            // RSA imposes size restriction on the object being encrypted (117 bytes).
            // Instead of sealing a Key object which is way over the size restriction,
            // we shall encrypt AES key in its byte format (using getEncoded() method).           
        }
        
        // Decrypt and extract a message from SealedObject
        public String decryptMsg(SealedObject encryptedMsgObj) {
            
            String plainText = null;
            
            // Amy and Bryan use the same AES key/transformation
            try {
				Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, sessionKey);
                plainText = (String)encryptedMsgObj.getObject(cipher);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (InvalidKeyException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (ClassNotFoundException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (IllegalBlockSizeException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (BadPaddingException e) {
				e.printStackTrace();
                System.exit(1);	
			} catch (IOException e) {
				e.printStackTrace();
                System.exit(1);	
			}
            
            
            
            return plainText;
        }
    }
}