
undefined4 *
FUN_08019e10(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            int param_5,undefined4 param_6,byte param_7)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int *piVar6;
  int local_50 [4];
  undefined4 *local_40;
  uint local_3c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined1 uStack_2c;
  
  piVar6 = local_50;
  local_3c = *(uint *)(param_5 + 0xc);
  local_40 = param_1;
  local_38 = param_3;
  local_34 = param_4;
  if ((local_3c & 1) == 0) {
    local_50[0] = param_5;
    local_50[1] = param_6;
    local_50[2] = (uint)param_7;
    FUN_08019cb0(&local_30,param_2,param_3,param_4);
    goto LAB_08019e4c;
  }
  iVar2 = FUN_08018fd4(param_5 + 0x6c);
  if (param_7 == 0) {
    iVar4 = *(int *)(iVar2 + 0x1c);
    iVar2 = *(int *)(iVar2 + 0x20);
  }
  else {
    iVar4 = *(int *)(iVar2 + 0x14);
    iVar2 = *(int *)(iVar2 + 0x18);
  }
  if (iVar2 < *(int *)(param_5 + 8)) {
    iVar3 = *(int *)(param_5 + 8) - iVar2;
    iVar1 = -(iVar3 * 4 + 7U & 0xfffffff8);
    piVar6 = (int *)((int)local_50 + iVar1);
    iVar5 = (int)&local_40 + iVar1;
    FUN_080269cc(iVar5,param_6,iVar3);
    *(undefined4 *)(param_5 + 8) = 0;
    if ((local_3c & 0xb0) != 0x20) {
      *(int *)((int)local_50 + iVar1) = iVar3;
      FUN_080195b4(&local_30,local_38,local_34,iVar5);
      local_38 = local_30;
      local_34 = CONCAT31(local_34._1_3_,uStack_2c);
      goto LAB_08019ef0;
    }
    *(int *)((int)local_50 + iVar1) = iVar2;
    FUN_080195b4(&local_30,local_38,local_34,iVar4);
    local_38 = local_30;
    local_34 = CONCAT31(local_34._1_3_,uStack_2c);
    *(int *)((int)local_50 + iVar1) = iVar3;
    iVar4 = iVar5;
  }
  else {
    *(undefined4 *)(param_5 + 8) = 0;
LAB_08019ef0:
    *piVar6 = iVar2;
  }
  FUN_080195b4(&local_30,local_38,local_34,iVar4);
LAB_08019e4c:
  local_34 = CONCAT31(local_34._1_3_,uStack_2c);
  *local_40 = local_30;
  local_40[1] = local_34;
  return local_40;
}

