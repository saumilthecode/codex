
undefined4 *
FUN_08011e48(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            int param_5,byte param_6,byte param_7)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined1 *puVar4;
  undefined1 *puVar5;
  int *piVar6;
  int local_58 [4];
  undefined1 auStack_48 [4];
  uint local_44;
  undefined4 *local_40;
  uint local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined1 uStack_2c;
  
  piVar6 = local_58;
  local_3c = *(uint *)(param_5 + 0xc);
  local_58[1] = (int)param_6;
  local_40 = param_1;
  local_38 = param_3;
  local_34 = param_4;
  if ((local_3c & 1) == 0) {
    local_58[0] = param_5;
    local_58[2] = (uint)param_7;
    FUN_08011ccc(&local_30,param_2,param_3,param_4);
    goto LAB_08011e88;
  }
  local_44 = local_58[1];
  iVar2 = FUN_0801139c(param_5 + 0x6c);
  if (param_7 == 0) {
    puVar4 = *(undefined1 **)(iVar2 + 0x1c);
    iVar2 = *(int *)(iVar2 + 0x20);
  }
  else {
    puVar4 = *(undefined1 **)(iVar2 + 0x14);
    iVar2 = *(int *)(iVar2 + 0x18);
  }
  if (iVar2 < *(int *)(param_5 + 8)) {
    iVar3 = *(int *)(param_5 + 8) - iVar2;
    iVar1 = -(iVar3 + 7U & 0xfffffff8);
    piVar6 = (int *)((int)local_58 + iVar1);
    puVar5 = auStack_48 + iVar1;
    FUN_08026922(puVar5,local_44,iVar3);
    *(undefined4 *)(param_5 + 8) = 0;
    if ((local_3c & 0xb0) != 0x20) {
      *(int *)((int)local_58 + iVar1) = iVar3;
      FUN_08011c98(&local_30,local_38,local_34,puVar5);
      local_38 = local_30;
      local_34 = CONCAT31(local_34._1_3_,uStack_2c);
      goto LAB_08011f2e;
    }
    *(int *)((int)local_58 + iVar1) = iVar2;
    FUN_08011c98(&local_30,local_38,local_34,puVar4);
    local_38 = local_30;
    local_34 = CONCAT31(local_34._1_3_,uStack_2c);
    *(int *)((int)local_58 + iVar1) = iVar3;
    puVar4 = puVar5;
  }
  else {
    *(undefined4 *)(param_5 + 8) = 0;
LAB_08011f2e:
    *piVar6 = iVar2;
  }
  FUN_08011c98(&local_30,local_38,local_34,puVar4);
LAB_08011e88:
  local_34 = CONCAT31(local_34._1_3_,uStack_2c);
  *local_40 = local_30;
  local_40[1] = local_34;
  return local_40;
}

