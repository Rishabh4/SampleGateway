package com.api.gateway.util;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;

public class EncryptDecrypt {
    private static final String SECRET_KEY = "Thisisatestkeyfo";
    private static final String secret = "VGhpc2lzYXRlc3RrZXlmbw==";

    public static String encrypt(String data) throws Exception {
        Key key = generateKey();
        Cipher c = Cipher.getInstance("AES");
        c.init(Cipher.ENCRYPT_MODE, key);
        byte[] encVal = c.doFinal(data.getBytes());
        String encryptedValue = Base64.getEncoder().encodeToString(encVal);
        return encryptedValue;
    }

    public static String decrypt(String encryptedData) throws Exception {
        try {
            Key key = generateKey();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, key);
            return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedData)));
        } catch (Exception e) {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    private static Key generateKey() throws Exception {
        byte[] decoded = Base64.getDecoder().decode(secret);
        Key key = new SecretKeySpec(decoded, "AES");
        return key;
    }

    public static String decodeKey() {
        byte[] decoded = Base64.getDecoder().decode(SECRET_KEY.getBytes());
        return new String(decoded);
    }

    public static String encodeKey() {
        byte[] encoded = Base64.getEncoder().encode(SECRET_KEY.getBytes());
        return new String(encoded);
    }
}