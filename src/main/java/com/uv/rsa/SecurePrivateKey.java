package com.uv.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;

/**
 * @author uvsun 2019-06-17 19:28
 */
public class SecurePrivateKey {
    private static final Decoder decoder = Base64.getDecoder();

    private byte[] keyBytes;

    private RSAPrivateKey privateKey;

    private Cipher cipher;

    public void setKeyByBase64String(String base64KeyString) throws InvalidKeySpecException, NoSuchAlgorithmException {
        this.setKeyBytes(decoder.decode(base64KeyString));
    }

    public byte[] getKeyBytes() {
        return keyBytes;
    }

    public void setKeyBytes(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.keyBytes = keyBytes;
        this.privateKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(this.keyBytes));
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public SecurePrivateKey(String base64KeyString) throws InvalidKeySpecException, NoSuchAlgorithmException {
        this.setKeyByBase64String(base64KeyString);
    }

    public SecurePrivateKey(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        this.setKeyBytes(keyBytes);
    }

    public SecurePrivateKey(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    /**
     * RSA公钥加密
     *
     * @param sourceData 原始未加密数据
     * @return 密文
     */
    public byte[] decrypt(byte[] sourceData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //RSA解密
        if (cipher == null) {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        }
        return cipher.doFinal(sourceData);
    }

}
