package pkaddress;

import org.junit.Test;
import org.yueweb3j.YueWeb3j;
import org.yueweb3j.crypto.Credentials;
import org.yueweb3j.utils.Numeric;

/**
 * @Author: OTTO
 * @Date: 2020-07-13 18:21
 */
public class PkAndAddress {
    @Test
    public void testPk(){
        YueWeb3j.init(0);
        Credentials credentials = Credentials.create("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");
        System.out.println(Numeric.toHexStringNoPrefix(credentials.getEcKeyPair().getPublicKey()));
        System.out.println(credentials.getAddress());

        YueWeb3j.init(1);
        credentials = Credentials.create("7631a11e9d28563cdbcf96d581e4b9a19e53ad433a53c25a9f18c74ddf492f75");
        System.out.println(Numeric.toHexStringNoPrefix(credentials.getEcKeyPair().getPublicKey()));
        System.out.println(credentials.getAddress());

    }
}
