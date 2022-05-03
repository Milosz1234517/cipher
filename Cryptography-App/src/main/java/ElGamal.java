import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.Base64;

public class ElGamal {

    private KeyPair keypair = null;
    private Cipher xCipher = null;
    private Cipher sCipher = null;


    public static void main(String[] args) throws IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        ElGamal e = new ElGamal();
        e.run();
        String[] x = e.encrypt("message");
        System.out.println(x[0]);
        System.out.println(e.decrypt(x));


    }

    public void run(){
        try {
            xCipher = Cipher.getInstance("ElGamal");
            sCipher = Cipher.getInstance("AES");

            KeyPairGenerator generator = KeyPairGenerator.getInstance("ELGamal");
            generator.initialize(512);
            keypair = generator.generateKeyPair();

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public String[] encrypt(String input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException {

        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256);
        Key sKey = generator.generateKey();
        xCipher.init(Cipher.ENCRYPT_MODE, keypair.getPublic());
        byte[] keyBlock = xCipher.doFinal(sKey.getEncoded());

        // Encryption step
        sCipher.init(Cipher.ENCRYPT_MODE, sKey);
        byte[] cipherText = sCipher.doFinal(input.getBytes());

        System.out.println("Elgamal keyBlock length: " + keyBlock.length);
        System.out.println("Elgamal cipherText length: " + cipherText.length);

        return new String[]{ Base64.getEncoder().encodeToString(cipherText), Base64.getEncoder().encodeToString(keyBlock)};
    }

    public String decrypt(String[] input) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] inputBytes = Base64.getDecoder().decode(input[0].getBytes(StandardCharsets.UTF_8));
        byte[] keyBlock = Base64.getDecoder().decode(input[1].getBytes(StandardCharsets.UTF_8));

        // Symmetric key unwrapping step
        xCipher.init(Cipher.DECRYPT_MODE, keypair.getPrivate());
        byte[] key = xCipher.doFinal(keyBlock);

        // Decryption step
        sCipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, 0, key.length, "AES"));
        byte[] plainText = sCipher.doFinal(inputBytes);

        return new String(plainText, StandardCharsets.UTF_8);
    }
}
