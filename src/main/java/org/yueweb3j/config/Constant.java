package org.yueweb3j.config;

//** Author: OTTO Date: 2020-07-03 17:13/
public class Constant {
    /**
     * 加密模式 0 原有 1 国密
     */
    public static int EncryptionMode = 1;

    /**
     * 系统证书合约地址
     */
    public static String SystemCertConstantAddress = "0x000000000000000000004341436572744c697374";

    /**
     * 系统权限合约地址
     */
    public static String SystemPermissionConstantAddress = "0x0000005065726d695461626c6541646472657373";

    /**
     * 零地址
     */
    public static String AddressZero = "0x0";

    /**
     * 合约权限修改的ID
     */
    public static enum ModifyPermissionType {
        //
        ModifyPerminType_Nil,
        ModifyPerminType_AddSendTxPerm,
        ModifyPerminType_DelSendTxPerm,
        ModifyPerminType_AddSendTxManagerPerm,
        ModifyPerminType_DelSendTxManagerPerm,
        ModifyPerminType_AddCrtContractPerm,
        ModifyPerminType_DelCrtContractPerm,
        ModifyPerminType_AddCrtContractManagerPerm,
        ModifyPerminType_DelCrtContractManagerPerm,
        ModifyPerminType_AddGropManagerPerm,
        ModifyPerminType_DelGropManagerPerm,
        ModifyPerminType_AddGropMemberPerm,
        ModifyPerminType_DelGropMemberPerm,
        //create permission for contract
        ModifyPerminType_CrtContractPerm,
        ModifyPerminType_AddContractMemberPerm,
        ModifyPerminType_DelContractMemberPerm,
        ModifyPerminType_AddContractManagerPerm,
        ModifyPerminType_DelContractManagerPerm,
        ModifyPerminType_AddWhitListPerm,
        ModifyPerminType_DelWhitListPerm,
        ModifyPerminType_AddBlockListPerm,
        ModifyPerminType_DelBlockListPerm,
        PerminType_SendTx,
        // this is memeber owner create contract perminssion
        PerminType_CreateContract,
        ModifyPerminType_DelGrop,
        ModifyPerminType_CrtGrop,
        PerminType_AccessContract
    }


    public static void main(String[] args) {
        System.out.println(ModifyPermissionType.ModifyPerminType_AddSendTxPerm.ordinal());
    }
}
