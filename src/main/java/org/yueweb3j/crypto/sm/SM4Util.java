package org.yueweb3j.crypto.sm;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

/**
 * 国密分组对称SM4加解密工具类
 * 当前模式支持：ECB、CBC、OFB、CFB
 * 算法PKCS5Padding、PKCS7Padding
 */
public class SM4Util {
    private transient Logger logger = LoggerFactory.getLogger(SM4Util.class);

    private volatile static SM4Util sm4Util;

    private SM4Util() {
    }

    public static SM4Util getInstance() {
        if (sm4Util == null) {
            synchronized (SM4Util.class) {
                if (sm4Util == null) {
                    sm4Util = new SM4Util();
                }
            }
        }
        return sm4Util;
    }

    /**
     * 生成SM4秘钥
     *
     * @param keySize
     * @return 返回为Base64编码的秘钥
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */
    public String generateKey(int keySize) throws NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator kg = KeyGenerator.getInstance("SM4", BouncyCastleProvider.PROVIDER_NAME);
        kg.init(keySize, new SecureRandom());
        byte[] keyByte = kg.generateKey().getEncoded();
        return Base64.toBase64String(keyByte);
    }


    /**
     * SM4加密
     *
     * @param msg           待机密明文
     * @param algorithmname 加密算法
     * @param secretkey     秘钥  这里传16byte秘钥的base64编码值
     * @param ivkey         初始向量 16byte 这里传16byte秘钥的base64编码值
     * @return 这里返回密文的base64编码值
     */
    public String SM4Encrypt(String msg, String algorithmname, String secretkey, String ivkey) {
        try {
            byte[] keyBytes = Base64.decode(secretkey);
            Security.addProvider(new BouncyCastleProvider());
            Key key = new SecretKeySpec(keyBytes, "SM4");
            Cipher in = Cipher.getInstance(algorithmname, "BC");
            if (algorithmname.contains("ECB")) {
                in.init(Cipher.ENCRYPT_MODE, key);
            } else if (algorithmname.contains("CBC") || algorithmname.contains("OFB") || algorithmname.contains("CFB")) {
                byte[] iv = Base64.decode(ivkey);
                in.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            }
            return Base64.toBase64String(in.doFinal(msg.getBytes("utf-8")));
        } catch (Exception e) {
            logger.error(ExceptionUtils.getStackTrace(e));
            return null;
        }
    }

    /**
     * SM4解密
     *
     * @param msg           待解密密文 这里传密文的base64编码值
     * @param algorithmname 加密算法
     * @param secretkey     加密秘钥  这里传16byte秘钥的base64编码值
     * @param ivkey         初始向量 16byte 这里传16byte IV的base64编码值
     * @return
     */
    public String SM4Decrypt(String msg, String algorithmname, String secretkey, String ivkey) {
        try {
            byte[] keyBytes = Base64.decode(secretkey);
            Security.addProvider(new BouncyCastleProvider());
            Key key = new SecretKeySpec(keyBytes, "SM4");
            Cipher out = Cipher.getInstance(algorithmname, "BC");
            if (algorithmname.contains("ECB")) {
                out.init(Cipher.DECRYPT_MODE, key);
            } else if (algorithmname.contains("CBC") || algorithmname.contains("OFB") || algorithmname.contains("CFB")) {
                byte[] iv = Base64.decode(ivkey);
                out.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
            }
            return new String(out.doFinal(Base64.decode(msg)), "utf-8");
        } catch (Exception e) {
            logger.error(ExceptionUtils.getStackTrace(e));
            return null;
        }
    }

    public static void main(String[] args) {
        try {
            System.out.println(SM4Util.getInstance().generateKey(128));
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }
}