package org.yueweb3j.protocol.core.methods.response.committee;

/**
 * received from fastBlock
 */
public class BlockMember {
    public String coinbase;
    public String committeeBase;
    public String publickey;
    public int flag;
    public int mType;

    public BlockMember() {
    }

    public BlockMember(String coinbase, String committeeBase, String publickey, int flag, int mType) {
        this.coinbase = coinbase;
        this.committeeBase = committeeBase;
        this.publickey = publickey;
        this.flag = flag;
        this.mType = mType;
    }

    public String getCoinbase() {
        return coinbase;
    }

    public void setCoinbase(String coinbase) {
        this.coinbase = coinbase;
    }

    public String getCommitteeBase() {
        return committeeBase;
    }

    public void setCommitteeBase(String committeeBase) {
        this.committeeBase = committeeBase;
    }

    public String getPublickey() {
        return publickey;
    }

    public void setPublickey(String publickey) {
        this.publickey = publickey;
    }

    public int getFlag() {
        return flag;
    }

    public void setFlag(int flag) {
        this.flag = flag;
    }

    public int getmType() {
        return mType;
    }

    public void setmType(int mType) {
        this.mType = mType;
    }

    @Override
    public String toString() {
        return "BlockMember{" +
                "coinbase='" + coinbase + '\'' +
                ", committeeBase='" + committeeBase + '\'' +
                ", publickey='" + publickey + '\'' +
                ", flag=" + flag +
                ", mType=" + mType +
                '}';
    }
}
