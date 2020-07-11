package org.yueweb3j.protocol.core.methods.response;

import org.yueweb3j.protocol.core.Response;
import org.yueweb3j.protocol.core.methods.response.permission.PermissionGroup;

import java.util.List;


public class YuePermissionGroup extends Response<PermissionGroup> {
   public PermissionGroup getPermissionGroup(){return getResult();}
}
