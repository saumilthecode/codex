
undefined4 *
FUN_080239ac(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,int param_9)

{
  uint *puVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  undefined1 uVar4;
  undefined4 uVar5;
  int iVar6;
  undefined4 local_40;
  undefined4 uStack_3c;
  undefined4 local_38;
  undefined4 local_34;
  int local_30;
  int local_2c [2];
  
  puVar1 = param_8;
  iVar6 = param_7;
  local_2c[0] = 0;
  local_38 = param_3;
  local_34 = param_4;
  uVar5 = FUN_0801126c(param_7 + 0x6c);
  FUN_080227e6(&local_40,param_2,local_38,local_34,param_5,param_6,&local_30,0,99,2,iVar6,local_2c);
  local_38 = local_40;
  local_34 = uStack_3c;
  if (local_2c[0] != 0) {
    *puVar1 = *puVar1 | 4;
    goto LAB_08023a6e;
  }
  iVar6 = FUN_08012ee0(&local_38,&param_5);
  local_40 = local_38;
  uStack_3c = local_34;
  if (iVar6 == 0) {
LAB_08023acc:
    if (local_30 < 0x45) {
      local_30 = local_30 + 100;
    }
  }
  else {
    uVar4 = FUN_08012e9c(&local_38);
    uVar3 = local_34;
    uVar2 = local_38;
    iVar6 = FUN_08010d04(uVar5,uVar4,0x2a);
    local_40 = uVar2;
    uStack_3c = uVar3;
    if (9 < (iVar6 - 0x30U & 0xff)) goto LAB_08023acc;
    FUN_08021b24(uVar2);
    local_30 = local_30 * 10 + (iVar6 - 0x30U);
    local_34 = 0xffffffff;
    iVar6 = FUN_08012ee0(&local_38,&param_5);
    local_40 = local_38;
    uStack_3c = local_34;
    if (iVar6 != 0) {
      uVar4 = FUN_08012e9c(&local_38);
      uVar3 = local_34;
      uVar2 = local_38;
      iVar6 = FUN_08010d04(uVar5,uVar4,0x2a);
      local_40 = uVar2;
      uStack_3c = uVar3;
      if ((iVar6 - 0x30U & 0xff) < 10) {
        FUN_08021b24(uVar2);
        local_30 = local_30 * 10 + (iVar6 - 0x30U);
        uStack_3c = 0xffffffff;
      }
    }
    local_30 = local_30 + -0x76c;
  }
  *(int *)(param_9 + 0x14) = local_30;
LAB_08023a6e:
  local_38 = local_40;
  local_34 = uStack_3c;
  iVar6 = FUN_08012eba(&local_38,&param_5);
  if (iVar6 != 0) {
    *puVar1 = *puVar1 | 2;
  }
  *param_1 = local_38;
  param_1[1] = local_34;
  return param_1;
}

