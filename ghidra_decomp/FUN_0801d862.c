
undefined4 *
FUN_0801d862(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,int param_9)

{
  uint *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  int iVar5;
  undefined4 uVar6;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined4 local_38;
  undefined4 local_34;
  int local_30;
  int local_2c [2];
  
  puVar1 = param_8;
  iVar5 = param_7;
  local_2c[0] = 0;
  local_38 = param_3;
  local_34 = param_4;
  uVar4 = FUN_08018e8c(param_7 + 0x6c);
  FUN_0801a826(&local_40,param_2,local_38,local_34,param_5,param_6,&local_30,0,99,2,iVar5,local_2c);
  local_38 = local_40;
  local_34 = uStack_3c;
  if (local_2c[0] != 0) {
    *puVar1 = *puVar1 | 4;
    goto LAB_0801d924;
  }
  iVar5 = FUN_0800e0fc(&local_38,&param_5);
  local_40 = local_38;
  uStack_3c = local_34;
  if (iVar5 == 0) {
LAB_0801d982:
    if (local_30 < 0x45) {
      local_30 = local_30 + 100;
    }
  }
  else {
    uVar6 = FUN_0800e0b8(&local_38);
    uVar3 = local_34;
    uVar2 = local_38;
    iVar5 = FUN_0800e0a0(uVar4,uVar6,0x2a);
    local_40 = uVar2;
    uStack_3c = uVar3;
    if (9 < (iVar5 - 0x30U & 0xff)) goto LAB_0801d982;
    FUN_080187b2(uVar2);
    local_30 = local_30 * 10 + (iVar5 - 0x30U);
    local_34 = 0xffffffff;
    iVar5 = FUN_0800e0fc(&local_38,&param_5);
    local_40 = local_38;
    uStack_3c = local_34;
    if (iVar5 != 0) {
      uVar6 = FUN_0800e0b8(&local_38);
      uVar3 = local_34;
      uVar2 = local_38;
      iVar5 = FUN_0800e0a0(uVar4,uVar6,0x2a);
      local_40 = uVar2;
      uStack_3c = uVar3;
      if ((iVar5 - 0x30U & 0xff) < 10) {
        FUN_080187b2(uVar2);
        local_30 = local_30 * 10 + (iVar5 - 0x30U);
        uStack_3c = 0xffffffff;
      }
    }
    local_30 = local_30 + -0x76c;
  }
  *(int *)(param_9 + 0x14) = local_30;
LAB_0801d924:
  local_38 = local_40;
  local_34 = uStack_3c;
  iVar5 = FUN_0800e0d6(&local_38,&param_5);
  if (iVar5 != 0) {
    *puVar1 = *puVar1 | 2;
  }
  *param_1 = local_38;
  param_1[1] = local_34;
  return param_1;
}

