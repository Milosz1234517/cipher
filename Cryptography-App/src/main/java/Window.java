import org.bouncycastle.util.test.FixedSecureRandom;
import org.bouncycastle.x509.X509CertificatePair;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;
import java.util.Iterator;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AccessDescription;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityInfoAccessExtension;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CRLDistributionPointsExtension;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.DNSName;
import sun.security.x509.DistributionPoint;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.GeneralName;
import sun.security.x509.GeneralNames;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.SerialNumber;
import sun.security.x509.SubjectAlternativeNameExtension;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.URIName;
import sun.security.x509.X500Name;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class Window {

    KeyStore ks;

    public static void main(String[] args) {
        Window w = new Window();
        try {
            w.createKeystore("newKeyStoreFileName", "password");
            w.loadKeystore("newKeyStoreFileName", "password");

            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(4096);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509Certificate[] chain = {w.generateCertificate("cn=Unknown", keyPair, 365, "SHA256withRSA")};

            w.ks.setKeyEntry("main", keyPair.getPrivate(), "654321".toCharArray(), chain);

            w.ks.store(new FileOutputStream("newKeyStoreFileName.jks"), "password".toCharArray());

            RSAPrivateKey pw = (RSAPrivateKey) w.ks.getKey("main", "654321".toCharArray());
            RSAPublicKey pu = (RSAPublicKey) w.ks.getCertificate("main").getPublicKey();

            Main main = new Main(pu.getModulus().bitLength());
            String t = main.encrypt("wow", pw);
            System.out.println(main.decrypt(t, pu));

            //System.out.println(ssoSigningKey.toString());

//            for (Iterator<String> it = w.ks.aliases().asIterator(); it.hasNext(); ) {
//                String s = it.next();
//                System.out.println(s);
//            }

        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void loadKeystore(String name, String password){
        try {
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(name + ".jks"), password.toCharArray());
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void createKeystore(String name, String password){
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] pwdArray = password.toCharArray();
            ks.load(null, pwdArray);

            FileOutputStream fos = new FileOutputStream(name + ".jks");
            ks.store(fos, pwdArray);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private X509Certificate generateCertificate(String dn, KeyPair keyPair, int validity, String sigAlgName) {
        try {
            PrivateKey privateKey = keyPair.getPrivate();

            X509CertInfo info = new X509CertInfo();

            Date from = new Date();
            Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

            CertificateValidity interval = new CertificateValidity(from, to);
            BigInteger serialNumber = new BigInteger(64, new SecureRandom());
            X500Name owner = new X500Name(dn);
            AlgorithmId sigAlgId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);

            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
            info.set(X509CertInfo.SUBJECT, owner);
            info.set(X509CertInfo.ISSUER, owner);
            info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(sigAlgId));

            // Sign the cert to identify the algorithm that's used.
            X509CertImpl certificate = new X509CertImpl(info);
            certificate.sign(privateKey, sigAlgName);

            // Update the algorith, and resign.
            sigAlgId = (AlgorithmId) certificate.get(X509CertImpl.SIG_ALG);
            info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, sigAlgId);
            certificate = new X509CertImpl(info);
            certificate.sign(privateKey, sigAlgName);

            return certificate;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }
}
