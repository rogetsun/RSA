package com.uv.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Base64.Decoder;

/**
 * @author uvsun 2019-06-17 19:28
 */
public class SecurePublicKey {
    private static final Decoder decoder = Base64.getDecoder();

    private byte[] keyBytes;

    private RSAPublicKey publicKey;
    private Cipher cipher;

    public void setKeyByBase64String(String base64KeyString) throws InvalidKeySpecException, NoSuchAlgorithmException {
        this.setKeyBytes(decoder.decode(base64KeyString));
    }

    public byte[] getKeyBytes() {
        return keyBytes;
    }

    public void setKeyBytes(byte[] keyBytes) throws NoSuchAlgorithmException, InvalidKeySpecException {
        this.keyBytes = keyBytes;
        this.publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(this.keyBytes));
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public SecurePublicKey(String base64KeyString) throws InvalidKeySpecException, NoSuchAlgorithmException {
        this.setKeyByBase64String(base64KeyString);
    }

    public SecurePublicKey(byte[] keyBytes) throws InvalidKeySpecException, NoSuchAlgorithmException {
        this.setKeyBytes(keyBytes);
    }

    public SecurePublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * RSA公钥加密
     *
     * @param sourceData 原始未加密数据
     * @return 密文
     */
    public byte[] encrypt(byte[] sourceData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException, InvalidKeySpecException {
        //RSA加密
        if (cipher == null) {
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        }
        return cipher.doFinal(sourceData);

    }

}
