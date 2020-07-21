package org.yueweb3j.protocol.core.methods.response;

import org.yueweb3j.protocol.core.Response;
import org.yueweb3j.protocol.core.methods.response.permission.PermissionGroup;

import java.util.List;
import java.util.Map;


public class YuePermissionGroup extends Response<Map<String,Object>> {
   public PermissionGroup getPermissionGroup(){
      Map<String, Object> result = getResult();
      if(result==null||result.size()==0){
         return null;
      }
      PermissionGroup permissionGroup=new PermissionGroup();
      permissionGroup.setGroupKey((String) result.get("Creator"));
      permissionGroup.setCreator((String) result.get("GroupKey"));
      permissionGroup.setId(((Integer)result.get("Id")).toString());
      permissionGroup.setName((String) result.get("name"));
      permissionGroup.setWhiteMembers((List<String>) result.get("WhiteMembers"));
      permissionGroup.setWhiteManager((List<String>) result.get("WhiteManager"));
      permissionGroup.setBlackMembers((List<String>) result.get("BlackMembers"));
      permissionGroup.setBlackManager((List<String>) result.get("BlackManager"));

      return permissionGroup;
   }

}
