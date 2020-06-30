package org.yueweb3j.abi.datatypes.generated;

import java.util.List;
import org.yueweb3j.abi.datatypes.StaticArray;
import org.yueweb3j.abi.datatypes.Type;

/**
 * Auto generated code.
 * <p><strong>Do not modifiy!</strong>
 * <p>Please use org.web3j.codegen.AbiTypesGenerator in the 
 * <a href="https://github.com/web3j/web3j/tree/master/codegen">codegen module</a> to update.
 */
public class StaticArray26<T extends Type> extends StaticArray<T> {
    @Deprecated
    public StaticArray26(List<T> values) {
        super(26, values);
    }

    @Deprecated
    @SafeVarargs
    public StaticArray26(T... values) {
        super(26, values);
    }

    public StaticArray26(Class<T> type, List<T> values) {
        super(type, 26, values);
    }

    @SafeVarargs
    public StaticArray26(Class<T> type, T... values) {
        super(type, 26, values);
    }
}
