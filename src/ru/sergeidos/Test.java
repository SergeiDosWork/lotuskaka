package ru.sergeidos;

import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.UrlBase64;
import org.bouncycastle.util.encoders.UrlBase64Encoder;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;

public class Test {

    private int i;

    public Test() {
        i = 0;
    }

    public void log() {
        System.out.println("Test message "+i);
        i += 1;
    }

    public String dummy(String teststring) {
        return "42 "+teststring;
    }

    public static void main(String[] args) throws FileNotFoundException {
        Test test = new Test();
        System.out.println(test.dummy("test string"));
        try {
            System.out.println(test.sign(new FileInputStream("E:\\Projects\\lotus\\store.jks"),"esia2016","esiacert","a"));
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public String sign(InputStream jksFile, String keyStorePassword, String certAlias, String dataToSign) throws Exception {

        PKCS7Signer signer = new PKCS7Signer();
        KeyStore keyStore = signer.loadKeyStore(jksFile,keyStorePassword);
        CMSSignedDataGenerator signatureGenerator = signer.setUpProvider(keyStore,certAlias,keyStorePassword);
        String content = dataToSign;
        byte[] signedBytes = signer.signPkcs7(content.getBytes("UTF-8"), signatureGenerator);
        return new String(UrlBase64.encode(signedBytes));

    }


}
