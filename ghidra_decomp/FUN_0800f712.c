
undefined4 *
FUN_0800f712(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,undefined4 param_9,
            byte param_10,byte param_11)

{
  uint *puVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  undefined4 local_58;
  undefined4 uStack_54;
  undefined4 local_50;
  undefined4 uStack_4c;
  undefined4 local_44;
  undefined4 uStack_40;
  undefined4 local_3c;
  undefined4 local_38;
  uint local_34;
  uint uStack_30;
  undefined4 local_2c;
  
  puVar1 = param_8;
  iVar3 = param_7;
  uVar5 = (uint)param_10;
  uVar4 = (uint)param_11;
  local_50 = param_3;
  uStack_4c = param_4;
  uVar2 = FUN_08018e8c(param_7 + 0x6c);
  *puVar1 = 0;
  local_38 = FUN_0800e0b2(uVar2,0x25);
  if (uVar4 == 0) {
    local_34 = uVar5;
    uStack_30 = 0;
  }
  else {
    local_2c = 0;
    local_34 = uVar4;
    uStack_30 = uVar5;
  }
  local_44 = 0;
  uStack_40 = 0;
  local_3c = 0;
  FUN_0800e6d8(&local_58,param_2,local_50,uStack_4c,param_5,param_6,iVar3,puVar1,param_9,&local_38,
               &local_44);
  local_50 = local_58;
  uStack_4c = uStack_54;
  FUN_0801fbe0(&local_44,param_9);
  iVar3 = FUN_0800e0d6(&local_50,&param_5);
  if (iVar3 != 0) {
    *puVar1 = *puVar1 | 2;
  }
  *param_1 = local_50;
  param_1[1] = uStack_4c;
  return param_1;
}

