
uint FUN_080260dc(undefined4 *param_1)

{
  uint uVar1;
  int iVar2;
  byte *pbVar3;
  int iVar4;
  
  iVar4 = *DAT_08026138;
  if ((iVar4 != 0) && (*(int *)(iVar4 + 0x20) == 0)) {
    FUN_08025ec4(iVar4);
  }
  if (-1 < (int)(param_1[0x19] << 0x1f)) {
    if (-1 < (int)((uint)*(ushort *)(param_1 + 3) << 0x16)) {
      FUN_08028650(param_1[0x16]);
    }
  }
  iVar2 = param_1[1];
  param_1[1] = iVar2 + -1;
  if (iVar2 + -1 < 0) {
    uVar1 = FUN_080262b4(iVar4,param_1);
  }
  else {
    pbVar3 = (byte *)*param_1;
    *param_1 = pbVar3 + 1;
    uVar1 = (uint)*pbVar3;
  }
  if ((-1 < (int)(param_1[0x19] << 0x1f)) && (-1 < (int)((uint)*(ushort *)(param_1 + 3) << 0x16))) {
    FUN_08028654(param_1[0x16]);
  }
  return uVar1;
}

