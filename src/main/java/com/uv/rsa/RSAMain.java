package com.uv.rsa;

import picocli.CommandLine;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author uvsun 2019-06-13 18:59
 */
public class RSAMain {

    private static SecureKeyPair sk;

    static {
        try {
            sk = SecureKeyPair.getInstance(SecureKeyPair.DEFAULT_SEED, SecureKeyPair.ALGORITHM_SHA1);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }


    public static void main(String[] args) {
//        execCmdArgsMode(args);
        execCmdParamMode(args);
    }

    /**
     * CmdParam命令行参数模式执行方法
     *
     * @param args
     */
    private static void execCmdParamMode(String[] args) {
        try {
            CmdParam app = CommandLine.populateCommand(new CmdParam(), args);
            System.out.println(app);
            if (app.isHelp()) {
                CommandLine.usage(app, System.out);
            } else if (app.getKeyName() != null) {
                generateKeyPair(app.getKeyName());
            } else {

                crypt(app);
            }
        } catch (Exception e) {
            System.out.println(e.getMessage());
            CommandLine.usage(new CmdParam(), System.out);
        }
        System.out.println("Done.");
    }

    /**
     * 加密 解密
     *
     * @param app 参数对象
     */
    private static void crypt(CmdParam app) {

        if (app.getFiles() == null || app.getFiles().length < 1) {
            System.out.println("请至少指定需要" +
                    (app.isDecrypt() ? "解密" : "加密") +
                    "的文件!");
            CommandLine.usage(app, System.out);
            return;
        }
        //需要解密解密的文件
        File sourceFile = new File(app.getFiles()[0]);
        if (!sourceFile.exists()) {
            System.out.println("需要" +
                    (app.isDecrypt() ? "解密" : "加密") +
                    "解密的文件[" +
                    sourceFile.toString() +
                    "]不存在!!");
        }
        //加密或解密后的文件字符串
        String distFileString;

        if (app.getFiles().length > 1) {
            distFileString = app.getFiles()[1];
        } else {
            String sFileName = sourceFile.getName();
            int dotIdx = sFileName.lastIndexOf(".");
            String oFileName = sFileName.substring(0, dotIdx) + (app.isDecrypt() ? "-decrypt" : "-encrypt") + sFileName.substring(dotIdx);
            if (sourceFile.getParent() == null) {
                distFileString = oFileName;
            } else {
                distFileString = sourceFile.getParent() + File.separator + oFileName;
            }
        }
        File distFile = new File(distFileString);
        //处理加密解密
        dealCrypt(sourceFile, distFile, app.isEncrypt(), app.getKeyFile());
    }

    private static void generateKeyPair(String keyPairName) throws NoSuchAlgorithmException {
        System.out.println(keyPairName);
        SecureKeyPair skp = SecureKeyPair.getInstance();
        File publicFile = new File(keyPairName + "-public.key");
        File privateFile = new File(keyPairName + "-private.key");
        System.out.println("ready to create " + publicFile + ", " + privateFile);
        FileOutputStream stream = null;
        try {
            stream = new FileOutputStream(publicFile);
            stream.write(skp.getPublicKey().getEncoded());
            stream.flush();
            stream.close();
            stream = new FileOutputStream(privateFile);
            stream.write(skp.getPrivateKey().getEncoded());
            stream.flush();

        } catch (Exception e) {
            System.out.println("创建密钥文件失败!");
            e.printStackTrace();
        } finally {
            try {
                if (stream != null) {
                    stream.close();
                }
            } catch (IOException e) {
                System.out.println("密钥文件写入流关闭失败");
                e.printStackTrace();
            }
        }
    }


    /**
     * 处理加密文件或解密文件
     *
     * @param sourceFile 源文件
     * @param distFile   解密或解密后生成的文件
     * @param isEncrypt  是否加密,不是加密就是解密
     * @param keyFile    密钥文件
     */
    private static void dealCrypt(File sourceFile, File distFile, boolean isEncrypt, File keyFile) {
        FileInputStream fis = null;
        FileOutputStream fos = null;


        try {
            /**
             * 读取密钥文件内容
             */
            byte[] keyBytes = null;
            if (keyFile != null && keyFile.exists()) {
                fis = new FileInputStream(keyFile);
                keyBytes = new byte[fis.available()];
                fis.read(keyBytes);
                fis.close();
                System.out.println("key file " + keyBytes.length + " bytes");
            }


            fis = new FileInputStream(sourceFile);
            fos = new FileOutputStream(distFile);
            byte[] sBytes = new byte[fis.available()];
            fis.read(sBytes);
            byte[] oBytes;

            //指定密钥加密或解密模式
            if (keyBytes != null) {
                System.out.println("special key " + (isEncrypt ? "加密" : "解密"));
            }
            //默认密钥加密解密模式
            else {
                System.out.println("default key " + (isEncrypt ? "加密" : "解密"));
            }

            if (isEncrypt) {
                oBytes = encrypt(sBytes, keyBytes);
            } else {
                oBytes = decrypt(sBytes, keyBytes);
            }
            fos.write(oBytes);
            fos.flush();
            System.out.println((!isEncrypt ? "解密" : "加密") + "生成" + oBytes.length + " bytes [" + distFile.getPath() + "]");
        } catch (Exception e) {
            System.out.println((!isEncrypt ? "解密" : "加密") + "失败");
            e.printStackTrace();
        } finally {
            try {
                if (null != fis) {
                    fis.close();
                }
                if (null != fos) {
                    fos.close();
                }
            } catch (Exception e) {

            }
        }
    }

    public static byte[] encrypt(byte[] bytes, byte[] keyBytes) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException, InvalidKeySpecException {
        if (null == sk && keyBytes == null) {
            return null;
        }
        if (null == bytes) {
            return null;
        }


        ByteBuffer buffer = ByteBuffer.wrap(bytes);
        int len = buffer.capacity() / SecureKeyPair.SOURCE_DATA_MAX_BYTE_LENGTH;
        if (buffer.capacity() % SecureKeyPair.SOURCE_DATA_MAX_BYTE_LENGTH > 0) {
            len++;
        }
        len = len * SecureKeyPair.SECURE_DATA_BYTE_LENGTH;

        ByteBuffer distBuffer = ByteBuffer.allocate(len);

        byte[] tmpBytes = new byte[SecureKeyPair.SOURCE_DATA_MAX_BYTE_LENGTH];
        SecurePublicKey securePublicKey = null;
        if (keyBytes != null) {
            securePublicKey = new SecurePublicKey(keyBytes);
        }
        while (buffer.hasRemaining()) {
            if (buffer.remaining() > SecureKeyPair.SOURCE_DATA_MAX_BYTE_LENGTH) {
                buffer.get(tmpBytes, 0, SecureKeyPair.SOURCE_DATA_MAX_BYTE_LENGTH);
                if (null != securePublicKey) {
                    distBuffer.put(securePublicKey.encrypt(tmpBytes));
                } else {
                    distBuffer.put(sk.encrypt(tmpBytes));
                }
            } else {
                byte[] tmpBytes2 = new byte[buffer.remaining()];
                buffer.get(tmpBytes2, 0, tmpBytes2.length);
                if (null != securePublicKey) {
                    distBuffer.put(securePublicKey.encrypt(tmpBytes2));
                } else {
                    distBuffer.put(sk.encrypt(tmpBytes2));
                }
            }
        }
        return distBuffer.array();
    }

    public static byte[] decrypt(byte[] bytes, byte[] keyBytes) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        if (null == sk && keyBytes == null) {
            return null;
        }
        if (null == bytes) {
            return null;
        }
        ByteBuffer deBuff = ByteBuffer.wrap(bytes);

        ByteBuffer sBuff = ByteBuffer.allocate(deBuff.capacity() / 64 * 53);
        byte[] tmpBytes = new byte[SecureKeyPair.SECURE_DATA_BYTE_LENGTH];

        SecurePrivateKey securePrivateKey = null;
        if (keyBytes != null) {
            securePrivateKey = new SecurePrivateKey(keyBytes);
        }

        while (deBuff.hasRemaining()) {
            deBuff.get(tmpBytes, 0, tmpBytes.length);
            if (null != securePrivateKey) {
                sBuff.put(securePrivateKey.decrypt(tmpBytes));
            } else {
                sBuff.put(sk.decrypt(tmpBytes));
            }

        }
        sBuff.flip();
        tmpBytes = new byte[sBuff.limit()];
        sBuff.get(tmpBytes, 0, tmpBytes.length);
        return tmpBytes;
    }


}
