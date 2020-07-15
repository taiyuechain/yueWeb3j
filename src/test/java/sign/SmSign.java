package sign;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.Test;
import org.yueweb3j.config.Constant;
import org.yueweb3j.contracts.system.SystemConstantFunctionEncoder;
import org.yueweb3j.crypto.*;
import org.yueweb3j.crypto.Sign.SignatureData;
import org.yueweb3j.crypto.sm.GmUtil;
import org.yueweb3j.protocol.Web3j;
import org.yueweb3j.protocol.core.DefaultBlockParameterName;
import org.yueweb3j.protocol.core.methods.response.YueGetTransactionCount;
import org.yueweb3j.protocol.core.methods.response.YueSendTransaction;
import org.yueweb3j.protocol.http.HttpService;
import org.yueweb3j.utils.Numeric;

import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;
import java.util.concurrent.ExecutionException;

import static org.yueweb3j.crypto.sm.GmUtil.rsAsn1ToPlainByteArray;

/**
 * @Author: OTTO
 * @Date: 2020-07-14 18:25
 */
public class SmSign {
    public  Web3j web3j = Web3j.build(new HttpService("http://39.99.195.63:7545"));

    public SignatureData signMessageSm(byte[] message, ECKeyPair keyPair, boolean needToHash) {
        BigInteger publicKey = keyPair.getPublicKey();
        System.out.println(Numeric.toHexStringNoPrefix(publicKey));
        byte[] messageHash;
        if (needToHash) {
            messageHash = GmUtil.sm3(message);
        } else {
            messageHash = message;
        }


        byte[] sigRS = GmUtil.signSm3WithSm2Asn1Rs(messageHash, GmUtil.defaultUserId,
                GmUtil.getPrivatekeyFromD(keyPair.getPrivateKey()));

        ASN1Sequence seq = ASN1Sequence.getInstance(sigRS);

        byte[] r = GmUtil.bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(0)).getValue());
        byte[] s = GmUtil.bigIntToFixexLengthBytes(ASN1Integer.getInstance(seq.getObjectAt(1)).getValue());
        byte[] v = new byte[]{(byte) 1};

        byte[] sigRS2 = rsAsn1ToPlainByteArray(sigRS);
        BigInteger r1 = new BigInteger(1, Arrays.copyOfRange(sigRS2, 0, 32));
        BigInteger s1 = new BigInteger(1, Arrays.copyOfRange(sigRS2, 32, 32 * 2));

        ECDSASignature sig = new ECDSASignature(r1, s1);


        int recId = -1;
        for (int i = 0; i < 4; i++) {
            BigInteger k = Sign.recoverFromSignature(i, sig, messageHash);
            if (k != null && k.equals(publicKey)) {
                recId = i;
                System.out.println(Numeric.toHexStringNoPrefix(k));
                break;
            }
        }

        return new SignatureData(v, r, s, keyPair.getCompressPublicKey());
    }

    @Test
    public void testRecoverPublicKeySM() {
        Credentials credentials = Credentials.create("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");
//        signMessageSm("111".getBytes(), credentials.getEcKeyPair(), true);
    }


    public static BigInteger getNonce(String address, Web3j web3j) {
        BigInteger count = null;
        try {
            YueGetTransactionCount ethGetTransactionCount =
                    web3j.yueGetTransactionCount(address, DefaultBlockParameterName.PENDING).sendAsync().get();
            count = ethGetTransactionCount.getTransactionCount();
        } catch (InterruptedException | ExecutionException e) {
            e.printStackTrace();
        }
        return count;
    }

    @Test
    public void sendTx() {
        long chainID = 19330;
//        Web3j web3j = Web3j.build(new HttpService("http://39.99.195.63:7545"));
        Credentials credentials = Credentials.create("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");
        BigInteger nonce = getNonce(credentials.getAddress(), web3j);

        RawTransaction rawTransaction = RawTransaction.createTransaction(BigInteger.ONE, BigInteger.ONE, BigInteger.ONE,
                credentials.getAddress(), BigInteger.ONE, "0x");

        byte[] signedMessage = TransactionEncoder.signMessage(rawTransaction, chainID, credentials);
        String hexValue = Numeric.toHexString(signedMessage);
        System.out.println(hexValue.replace("0x", ""));
        try {
            YueSendTransaction result = web3j.yueSendRawTransaction(hexValue).send();
            System.out.println(result.getTransactionHash());
            if (result.getTransactionHash() != null) {
                System.out.println("abc");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    @Test
    public void testGrantPermission() {
        String address = "0x0000000000000000000000000000000000000000";
        System.out.println();
        String yan = SystemConstantFunctionEncoder.getGrantPermission("grantPermission", Constant.SystemPermissionConstantAddress, address, address, Constant.ModifyPermissionType.ModifyPerminType_AddBlockListPerm.ordinal(), false);
        System.out.println(yan);
    }

}
