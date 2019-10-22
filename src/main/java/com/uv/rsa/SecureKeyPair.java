package com.uv.rsa;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * @author uvsun 2019-06-14 21:53
 * 密钥封装类
 * <p>
 * 每次使用同样的随机数种子和算法,会有同样的假随机数序列,用同样的假随机数序列第N次生成的密钥对也就相同
 * 注意:不指定会使用本地算法 NativePRNG, 就算种子相同也没有相同的假随机数序列了.因为在运行机器上并不是同样的第N次了.
 */
public class SecureKeyPair {

    /**
     * 默认安全随机数种子
     */
    public static final byte[] DEFAULT_SEED = "jj3csGt2iZlv4XXSbnxwpWwa4lQx1w==".getBytes();

    /**
     * 每次使用同样的随机数算法,不指定会使用本地算法
     */
    public static final String ALGORITHM_SHA1 = "SHA1PRNG";
    /**
     * 本地随机数算法不会生成一样的随机数序列.
     */
    public static final String ALGORITHM_NATIVE = "NativePRNG";
    /**
     * 默认密钥大小
     */
    public static final int DEFAULT_RSA_BIT_LENGTH = 512;
    /**
     * 默认密钥大小的密钥一次加密最大byte字节数
     */
    public static final int SOURCE_DATA_MAX_BYTE_LENGTH = 53;

    /**
     * 默认密钥大小的密钥加密一次后对应密文大小
     */
    public static final int SECURE_DATA_BYTE_LENGTH = 64;


    /**
     * 私钥
     */
    private RSAPrivateKey privateKey;
    /**
     * 公钥
     */
    private RSAPublicKey publicKey;

    private Cipher encryptCipher;
    private Cipher decryptCipher;

    /**
     * RSA公钥加密
     *
     * @param sourceData 原始未加密数据
     * @return 密文
     */
    public byte[] encrypt(byte[] sourceData) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //RSA加密
        if (encryptCipher == null) {
            encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, this.publicKey);
        }
        return encryptCipher.doFinal(sourceData);
    }

    /**
     * RSA私钥解密
     *
     * @param secureData 加密数据
     * @return 明文
     */
    public byte[] decrypt(byte[] secureData) throws NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException {
        //RSA解密
        if (decryptCipher == null) {
            decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, this.privateKey);
        }
        return decryptCipher.doFinal(secureData);
    }

    /**
     * 生成密钥对
     *
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecureKeyPair getInstance() throws NoSuchAlgorithmException {
        return getInstance(new SecureRandom());
    }

    /**
     * 用指定安全随机数对象生成密钥对
     *
     * @param secureRandom
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecureKeyPair getInstance(SecureRandom secureRandom) throws NoSuchAlgorithmException {
        // KeyPairGenerator类用于生成公钥和私钥对，基于RSA算法生成对象
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        // 初始化密钥对生成器，密钥大小为512-1024位
        keyPairGen.initialize(DEFAULT_RSA_BIT_LENGTH, secureRandom);
        // 生成一个密钥对，保存在keyPair中
        KeyPair keyPair = keyPairGen.generateKeyPair();
        // 得到私钥
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        // 得到公钥
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return new SecureKeyPair(publicKey, privateKey);
    }

    /**
     * 用指定的安全随机数种子和随机算法生成密钥对.
     *
     * @param seed      种子
     * @param algorithm 随机数算法
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static SecureKeyPair getInstance(byte[] seed, String algorithm) throws NoSuchAlgorithmException {
        SecureRandom secureRandom = SecureRandom.getInstance(algorithm);
        if (null != seed) {
            secureRandom.setSeed(seed);
        }
        return getInstance(secureRandom);
    }

    /**
     * 生成安全随机数种子,可用于创建安全随机数对象
     *
     * @param numBytes
     * @return
     */
    public static byte[] generateSeed(int numBytes) {
        return SecureRandom.getSeed(numBytes);
    }


    public SecureKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;

    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(RSAPrivateKey privateKey) {
        this.privateKey = privateKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(RSAPublicKey publicKey) {
        this.publicKey = publicKey;
    }

}
