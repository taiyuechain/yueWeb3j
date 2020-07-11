package org.yueweb3j.contracts.system;

import org.yueweb3j.abi.FunctionEncoder;
import org.yueweb3j.abi.TypeReference;
import org.yueweb3j.abi.datatypes.*;
import org.yueweb3j.abi.datatypes.generated.Uint256;
import org.yueweb3j.config.Constant;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;


public class SystemConstantFunctionEncoder {

    private static Type getInputParams(Object o) {
        if (o instanceof byte[]) {
            return new DynamicBytes((byte[]) o);
        } else if (o instanceof String) {
            return new Address((String) o);
        } else if (o instanceof Boolean) {
            return new Bool((Boolean) o);
        } else if (o instanceof BigInteger) {
            return new Uint256((BigInteger) o);
        }
        return null;
    }
    private static Type getInputParamsRealString(String s){
        return new Utf8String(s);
    }

    private static TypeReference<?> getOutputParams(Object o) {
        if (o instanceof Uint256) {
            return new TypeReference<Uint256>() {
            };
        } else if (o instanceof Bool) {
            return new TypeReference<Bool>() {
            };
        }else if (o instanceof String){
            return new TypeReference<Utf8String>() {
            };
        }
        return null;
    }

    private static String makeFunction(String name, List<Type> input, List<TypeReference<?>> output) {
        Function function = new Function(name, input, output);
        return FunctionEncoder.encode(function);
    }

    private static String makeFunction(String name, List<Type> input) {
        List<TypeReference<?>> output = new ArrayList<>();
        Function function = new Function(name, input, output);
        return FunctionEncoder.encode(function);
    }

    /**
     * 添加成员或者删除委员会成员
     *
     * @param senderCert 授权证书的Byte，这个byte必须是解码以后的
     * @param caCert     新入证书Byte
     * @param publicKey  新入证书pk
     * @param address    新入证书地址
     * @param isAdd      添加标记
     * @return 编码后的function
     */
    public static String getMultiProposal(byte[] senderCert, byte[] caCert, byte[] publicKey, String address, boolean isAdd) {
        String functionName = "multiProposal";
        List<Type> inputParameters = new ArrayList<>();
        inputParameters.add(getInputParams(senderCert));
        inputParameters.add(getInputParams(caCert));
        inputParameters.add(getInputParams(publicKey));
        inputParameters.add(getInputParams(address));
        inputParameters.add(getInputParams(isAdd));
        return makeFunction(functionName, inputParameters);
    }


    /**
     * 获取组创建function
     * @param groupName 组名字
     * @return 编码后的function
     */
    public static String getCreateGroupPermission(String groupName){
        String functionName ="createGroupPermission";
        List<Type> inputParameters = new ArrayList<>();
        inputParameters.add(getInputParamsRealString(groupName));
        List<TypeReference<?>> outputParameters = new ArrayList<>();
        outputParameters.add(getOutputParams("1"));
        return makeFunction(functionName,inputParameters,outputParameters);
    }

    /**
     * 获取组删除function
     * @param groupAddress 组名字
     * @return 编码后的function
     */
    public static String getDelGroupPermission(String groupAddress){
        String functionName ="delGroupPermission";
        List<Type> inputParameters = new ArrayList<>();
        inputParameters.add(getInputParamsRealString(groupAddress));
        return makeFunction(functionName,inputParameters);
    }

    /**
     * 权限
     *
     * @param name  合约方法
     * @param contractAddr    合约地址
     * @param memberAddr      成员地址
     * @param groupAddr       组地址
     * @param type            权限代码
     * @param whitelistIsWork 是否创建合约
     * @return 编码后的function
     */
    public static String getGrantPermission(String name, String contractAddr, String memberAddr, String groupAddr, Integer type,
                                            Boolean whitelistIsWork) {
        String functionName = name;
        List<Type> inputParameters = new ArrayList<>();
        if (null == contractAddr) {
            inputParameters.add(getInputParams(Constant.AddressZero));
        } else {
            inputParameters.add(getInputParams(contractAddr));
        }
        if (null == memberAddr) {
            inputParameters.add(getInputParams(Constant.AddressZero));
        } else {
            inputParameters.add(getInputParams(memberAddr));
        }
        if (null == groupAddr) {
            inputParameters.add(getInputParams(Constant.AddressZero));
        } else {
            inputParameters.add(getInputParams(groupAddr));
        }
        inputParameters.add(getInputParams(type));
        inputParameters.add(getInputParams(whitelistIsWork));
        return makeFunction(functionName, inputParameters);
    }

    private static String getGrantPermission(String name, String contractAddr, String memberAddr, String groupAddr, Integer type) {
        return getGrantPermission(name, contractAddr, memberAddr, groupAddr, type, false);
    }

    private static String getAddGrantPermission(String contractAddr, String memberAddr, String groupAddr, Integer type,
                                                Boolean whitelistIsWork) {
        return getGrantPermission("grantPermission", contractAddr, memberAddr, groupAddr, type, whitelistIsWork);
    }

    private static String getAddGrantPermission(String contractAddr, String memberAddr, String groupAddr, Integer type) {
        return getAddGrantPermission(contractAddr, memberAddr, groupAddr, type, false);
    }

    private static String getRemoveGrantPermission(String contractAddr, String memberAddr, String groupAddr, Integer type,
                                                   Boolean whitelistIsWork) {
        return getGrantPermission("revokePermission", contractAddr, memberAddr, groupAddr, type, whitelistIsWork);
    }

    private static String getRemoveGrantPermission(String contractAddr, String memberAddr, String groupAddr, Integer type) {
        return getRemoveGrantPermission(contractAddr, memberAddr, groupAddr, type, false);
    }

    /**
     * 获取增加交易权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getAddSendTxPerm(String memberOrGroupAddress) {
        return getAddGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_AddSendTxPerm.ordinal());
    }

    /**
     * 获取删除交易权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getDelSendTxPerm(String memberOrGroupAddress) {
        return getRemoveGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_DelSendTxPerm.ordinal());
    }

    /**
     * 获取添加交易管理权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getAddSendTxManagerPerm(String memberOrGroupAddress) {
        return getAddGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_AddSendTxManagerPerm.ordinal());
    }

    /**
     * 获取删除交易管理权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getDelSendTxManagerPerm(String memberOrGroupAddress) {
        return getRemoveGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_DelSendTxManagerPerm.ordinal());
    }

    /**
     * 获取添加合约权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getAddCrtContractPerm(String memberOrGroupAddress) {
        return getRemoveGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_AddCrtContractPerm.ordinal());
    }

    /**
     * 获取删除合约权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getDelCrtContractPerm(String memberOrGroupAddress) {
        return getRemoveGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_DelCrtContractPerm.ordinal());
    }

    /**
     * 获取添加合约管理权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getAddCrtContractManagerPerm(String memberOrGroupAddress) {
        return getAddGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_AddCrtContractManagerPerm.ordinal());
    }

    /**
     * 获取删除合约管理权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getDelCrtContractManagerPerm(String memberOrGroupAddress) {
        return getRemoveGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_DelCrtContractManagerPerm.ordinal());
    }



    /**
     * 获取添加组管理权限function
     *
     * @param member 成员
     * @param groupAddress 组地址
     * @return 编码后的function
     */
    public static String getAddGropManagerPerm(String member,String groupAddress) {
        return getAddGrantPermission(null, member, groupAddress,
                Constant.ModifyPermissionType.ModifyPerminType_AddGropManagerPerm.ordinal());
    }

    /**
     *  获取删除组管理权限function
     * @param member 成员
     * @param groupAddress 组地址
     * @return 编码后的function
     */
    public static String getDelCrtContractPerm(String member,String groupAddress) {
        return getRemoveGrantPermission(null, member, groupAddress,
                Constant.ModifyPermissionType.ModifyPerminType_DelGropManagerPerm.ordinal());
    }

    /**
     * 获取添加组成员权限
     *
     * @param member 成员
     * @param groupAddress 组地址
     * @return 编码后的function
     */
    public static String getAddGropMemberPerm(String member,String groupAddress) {
        return getAddGrantPermission(null, member, groupAddress,
                Constant.ModifyPermissionType.ModifyPerminType_AddGropMemberPerm.ordinal());
    }

    /**
     * 获取删除合约管理权限function
     *
     * @param member 成员
     * @param groupAddress 组地址
     * @return 编码后的function
     */
    public static String getDelGropMemberPerm(String member,String groupAddress) {
        return getRemoveGrantPermission(null,member, groupAddress,
                Constant.ModifyPermissionType.ModifyPerminType_DelGropMemberPerm.ordinal());
    }


    /**
     * 获取添加合约成员权限function
     *
     * @param member 成员
     * @param contractAddress 组地址
     * @return 编码后的function
     */
    public static String getAddContractMemberPerm(String member,String contractAddress) {
        return getAddGrantPermission(contractAddress, member, null,
                Constant.ModifyPermissionType.ModifyPerminType_AddContractMemberPerm.ordinal());
    }

    /**
     * 获取删除合约成员权限function
     *
     * @param member 成员
     * @param contractAddress 组地址
     * @return 编码后的function
     */
    public static String getDelContractMemberPerm(String member,String contractAddress) {
        return getRemoveGrantPermission(contractAddress, member, null,
                Constant.ModifyPermissionType.ModifyPerminType_DelContractMemberPerm.ordinal());
    }

    /**
     * 获取添加组成员管理权限
     *
     * @param member 成员
     * @param contractAddress 组地址
     * @return 编码后的function
     */
    public static String getAddContractManagerPerm(String member,String contractAddress) {
        return getAddGrantPermission(contractAddress, member, null,
                Constant.ModifyPermissionType.ModifyPerminType_AddContractManagerPerm.ordinal());
    }

    /**
     * 获取删除组成员管理权限
     *
     * @param member 成员
     * @param contractAddress 组地址
     * @return 编码后的function
     *
     */
    public static String getDelContractManagerPerm(String member,String contractAddress){
        return getRemoveGrantPermission(contractAddress,member, null,
                Constant.ModifyPermissionType.ModifyPerminType_DelContractManagerPerm.ordinal());
    }

    /**
     * 获取添加白名单权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getAddWhitListPerm(String memberOrGroupAddress) {
        return getAddGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_AddWhitListPerm.ordinal());
    }

    /**
     * 获取删除白名单权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getDelWhitListPerm(String memberOrGroupAddress) {
        return getRemoveGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_DelWhitListPerm.ordinal());
    }

    /**
     * 获取添加黑名单权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getAddBlockListPerm(String memberOrGroupAddress) {
        return getAddGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_AddBlockListPerm.ordinal());
    }

    /**
     * 获取删除黑名单权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getDelBlockListPerm(String memberOrGroupAddress) {
        return getRemoveGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.ModifyPerminType_DelBlockListPerm.ordinal());
    }


    /**
     * 获取创建合约权限function
     *
     * @param memberOrGroupAddress 成员或组地址
     * @return 编码后的function
     */
    public static String getCreateContract(String memberOrGroupAddress) {
        return getRemoveGrantPermission(null, memberOrGroupAddress, null,
                Constant.ModifyPermissionType.PerminType_CreateContract.ordinal());
    }


}
