package org.yueweb3j.crypto.sm;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.bouncycastle.asn1.gm.GMNamedCurves;
import org.bouncycastle.asn1.gm.GMObjectIdentifiers;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * 国密SM2加解密工具类
 * 椭圆参数 sm2p256v1
 */
public class SM2Util {

    private transient Logger logger = LoggerFactory.getLogger(SM2Util.class);

    private volatile static SM2Util sm2Util;

    private SM2Util() {
    }

    public static SM2Util getInstance() {
        if (sm2Util == null) {
            synchronized (SM2Util.class) {
                if (sm2Util == null) {
                    sm2Util = new SM2Util();
                }
            }
        }
        return sm2Util;
    }

    /**
     * 生成秘钥对
     *
     * @return
     */
    public KeyPair createKeyPair() throws Exception {
        // 获取SM2 椭圆曲线推荐参数
        X9ECParameters ecParameters = GMNamedCurves.getByName("sm2p256v1");
        // 构造EC 算法参数
        ECNamedCurveParameterSpec sm2Spec = new ECNamedCurveParameterSpec(
                // 设置SM2 算法的 OID
                GMObjectIdentifiers.sm2p256v1.toString()
                // 设置曲线方程
                , ecParameters.getCurve()
                // 椭圆曲线G点
                , ecParameters.getG()
                // 大整数N
                , ecParameters.getN());
        // 创建 密钥对生成器
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", new BouncyCastleProvider());
        // 使用SM2的算法区域初始化密钥生成器
        gen.initialize(sm2Spec, new SecureRandom());
        // 获取密钥对
        KeyPair keyPair = gen.generateKeyPair();
        System.out.println("SM2私钥：");
        System.out.println(Base64.toBase64String(keyPair.getPrivate().getEncoded()));
        System.out.println("SM2公钥：");
        System.out.println(Hex.encode(keyPair.getPublic().getEncoded()));
        System.out.println(Base64.toBase64String(keyPair.getPublic().getEncoded()));
        return keyPair;
    }

    /**
     * SM2公钥加密
     *
     * @param enData    待加密明文
     * @param publickey SM2公钥（base64编码值）
     * @return 返回密文的base64编码值
     */
    public String SM2Encrypt(String enData, String publickey) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            byte[] sourceData = enData.getBytes();
            Cipher cp1 = Cipher.getInstance("SM2");
            // 解密由base64编码的公钥
            byte[] keyBytes = Base64.decode(publickey);
            // 构造X509EncodedKeySpec对象
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            // KEY_ALGORITHM 指定的加密算法
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            // 取公钥匙对象
            PublicKey pubkey = keyFactory.generatePublic(keySpec);
            // 加密
            cp1.init(Cipher.ENCRYPT_MODE, pubkey);
            return Base64.toBase64String(cp1.doFinal(sourceData));
        } catch (Exception e) {
            logger.error(ExceptionUtils.getStackTrace(e));
            return null;
        }
    }

    /**
     * SM2私钥解密
     *
     * @param data       待解密数据 base64编码值
     * @param privateKey SM2私钥
     * @return 返回解密后明文
     */
    public String SM2Decrypt(String data, String privateKey) {
        try {
            Security.addProvider(new BouncyCastleProvider());
            Cipher cp2 = Cipher.getInstance("SM2");
            byte[] keyBytes = Base64.decode(privateKey);
            byte[] decryData = Base64.decode(data);
            // 构造PKCS8EncodedKeySpec对象
            PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
            // KEY_ALGORITHM 指定的加密算法
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            // 取私钥匙对象
            PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
            cp2.init(Cipher.DECRYPT_MODE, priKey);
            return new String(cp2.doFinal(decryData), "utf-8");
        } catch (Exception e) {
            logger.error(ExceptionUtils.getStackTrace(e));
            return null;
        }
    }

    /**
     * SM2签名
     *
     * @param data
     * @param privateKey
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public String SM2Sign(String data, String privateKey) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] keyBytes = Base64.decode(privateKey);
        byte[] signData = data.getBytes();
        // 构造PKCS8EncodedKeySpec对象
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        // 取私钥匙对象
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature sig = Signature.getInstance("SM3withSM2", "BC");
        sig.initSign(priKey);
        sig.update(signData);
        return Base64.toBase64String(sig.sign());
    }


    /**
     * SM2验签
     *
     * @param data
     * @param publickey
     * @param signMsg
     * @return
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidKeyException
     * @throws SignatureException
     */
    public boolean SM2Verify(String data, String publickey, String signMsg) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] pubBytes = Base64.decode(publickey);
        byte[] sourceData = data.getBytes();
        byte[] signData = Base64.decode(signMsg);
        Signature sign = Signature.getInstance("SM3withSM2", "BC");
        // 构造X509EncodedKeySpec对象
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(pubBytes);
        // KEY_ALGORITHM 指定的加密算法
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        // 取公钥匙对象
        PublicKey pubkey = keyFactory.generatePublic(keySpec);
        sign.initVerify(pubkey);
        sign.update(sourceData);
        return sign.verify(signData);
    }


    public static void main(String[] args) {
        try {
//            SM2Util.getInstance().createKeyPair();
//
//            String temp = SM2Util.getInstance().SM2Encrypt("中国", "MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAEvDgDy5BfKrG6RPzMarBpQ6GAO4aPIt22uS3KoCZa9lBoz4/uq8BXGkw+hz/rZNjzA83jJjrlURq/89owPsKbdw==");
//            System.out.println(temp);
//            System.out.println(SM2Util.getInstance().SM2Decrypt(temp, "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgbyRdoh+cuOrnwaQ40FTj9Xz9oaHvN61B/n22ghMkBJugCgYIKoEcz1UBgi2hRANCAAS8OAPLkF8qsbpE/MxqsGlDoYA7ho8i3ba5LcqgJlr2UGjPj+6rwFcaTD6HP+tk2PMDzeMmOuVRGr/z2jA+wpt3"));
//
//
            for (int i = 0; i < 10; i++) {
//                System.out.println(SM2Util.getInstance().SM2Sign(Numeric.toHexStringNoPrefix(Hash.sha3("1234".getBytes())), "MIGTAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBHkwdwIBAQQgbyRdoh+cuOrnwaQ40FTj9Xz9oaHvN61B/n22ghMkBJugCgYIKoEcz1UBgi2hRANCAAS8OAPLkF8qsbpE/MxqsGlDoYA7ho8i3ba5LcqgJlr2UGjPj+6rwFcaTD6HP+tk2PMDzeMmOuVRGr/z2jA+wpt3"));
            }
//            SM2Util.getInstance().createKeyPair();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}