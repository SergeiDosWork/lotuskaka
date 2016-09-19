package ru.sergeidos;

import org.apache.http.NameValuePair;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.utils.URIUtils;
import org.apache.http.client.utils.URLEncodedUtils;
import org.apache.http.message.BasicNameValuePair;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.util.encoders.UrlBase64;

import java.io.FileInputStream;
import java.net.URI;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Created by SergeiDos on 19.09.2016.
 */
public class Foo {

    public static void main(String[] args) throws Exception {

        String client_id = "ASED01741";
//        String state = "550e8400-e29b-41d4-a716-446655440000";
//        String state = "048c4af9-2f17-4612-8e73-e7eeeffbb47f";
        String state = UUID.randomUUID().toString();

        String scope = "http://esia.gosuslugi.ru/usr_inf";

        String timestamp = "2016.09.19 22:54:11 +0500"
                ;// ("yyyy.MM.dd HH:mm:ss +0000");
        String access_type = "online";
        String response_type = "code";
        String redirect_uri = "https://develop.project-osnova.ru/osnova2/login.nsf/esialogin.xsp";  //адресс редиректа, после того как пользователь ввел данные в есиа
        String client_secret = "";
        //Генерим подпись с помощью нашего сертификата
        String msg = scope + timestamp + client_id + state;
        byte[] msgBytes =  msg.getBytes("UTF-8");

        PKCS7Signer signer = new PKCS7Signer();
        KeyStore keyStore = signer.loadKeyStore(new FileInputStream("E:\\Projects\\lotus\\store.jks"),"esia2016");
        CMSSignedDataGenerator signatureGenerator = signer.setUpProvider(keyStore,"esiacert","esia2016");
        byte[] signedBytes = signer.signPkcs7(msgBytes, signatureGenerator);

        client_secret = new String(UrlBase64.encode(signedBytes));
        //генерим строку с параметрами

        List<NameValuePair> qparams = new ArrayList<NameValuePair>();
        qparams.add(new BasicNameValuePair("client_id", client_id));
        qparams.add(new BasicNameValuePair("client_secret", client_secret));
        qparams.add(new BasicNameValuePair("redirect_uri", redirect_uri));
        qparams.add(new BasicNameValuePair("scope", scope));
        qparams.add(new BasicNameValuePair("response_type", response_type));
        qparams.add(new BasicNameValuePair("state", state));
        qparams.add(new BasicNameValuePair("timestamp", timestamp));
        qparams.add(new BasicNameValuePair("access_type", access_type));



        URI uri = URIUtils.createURI("https", "esia-portal1.test.gosuslugi.ru", -1, "aas/oauth2/ac",
                URLEncodedUtils.format(qparams, "UTF-8"), null);
        HttpGet httpget = new HttpGet(uri);
        System.out.println(httpget.getURI());

    }
}
