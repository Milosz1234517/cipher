import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Base64;

import javax.crypto.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;


public class Main {

    Cipher cipher;
    int maxBytesEncrypt;
    int maxBytesDecrypt;

    public String encrypt(String message, RSAPrivateKey privateKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] plainText = message.getBytes();
        int counter = 0;
        byte[] bytes = new byte[0];

        while (counter < plainText.length) {
            byte[] tmp;

            if (counter + maxBytesEncrypt < plainText.length) {
                tmp = new byte[maxBytesEncrypt];
            } else tmp = new byte[plainText.length - counter];

            int loop = plainText.length - counter;

            for (int i = 0; i < loop; i++) {
                if (i == maxBytesEncrypt) break;
                tmp[i] = plainText[counter];
                counter++;
            }

            byte[] cipherText = cipher.doFinal(tmp);

            for (byte b : cipherText) {
                bytes = Arrays.append(bytes, b);
            }
        }

        return Base64.toBase64String(bytes);
    }

    public String decrypt(String decryptedMessage, RSAPublicKey publicKey) throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] decode = Base64.decode(decryptedMessage);
        int counter = 0;
        StringBuilder resultDecrypt = new StringBuilder();

        while (counter < decode.length) {

            byte[] tmp = new byte[maxBytesDecrypt];

            for (int i = 0; i < decode.length; i++) {
                if (i == maxBytesDecrypt) break;
                tmp[i] = decode[counter];
                counter++;
            }

            byte[] cipherText = cipher.doFinal(tmp);
            resultDecrypt.append(new String(cipherText));
        }

        return resultDecrypt.toString();
    }

    public void run() {
        try {
            cipher = Cipher.getInstance("RSA");

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(600);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();

            int keySize = publicKey.getModulus().bitLength();
            maxBytesDecrypt = (int) Math.floor((keySize/8.0));
            maxBytesEncrypt = (int) Math.floor((keySize/8.0)) - 11;

            String enc = encrypt("elo", privateKey);

            System.out.println(decrypt(enc, publicKey));

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public Main(int keySize) {
        try {
            cipher = Cipher.getInstance("RSA");
            maxBytesDecrypt = (int) Math.floor((keySize/8.0));
            maxBytesEncrypt = (int) Math.floor((keySize/8.0)) - 11;
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        Security.addProvider(new BouncyCastleProvider());
        new Main(1024).run();
    }

}
