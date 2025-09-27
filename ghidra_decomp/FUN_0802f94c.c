
uint FUN_0802f94c(int param_1,byte param_2,undefined4 *param_3,undefined4 param_4)

{
  ushort uVar1;
  int iVar2;
  uint uVar3;
  byte *pbVar4;
  int iVar5;
  
  if ((param_1 != 0) && (*(int *)(param_1 + 0x34) == 0)) {
    FUN_08025ec4();
  }
  uVar1 = *(ushort *)(param_3 + 3);
  iVar5 = (int)(short)uVar1;
  iVar2 = param_3[6];
  param_3[2] = iVar2;
  if ((iVar5 << 0x1c < 0) && (iVar2 = param_3[4], iVar2 != 0)) {
    uVar3 = param_3[0x19];
  }
  else {
    iVar2 = FUN_08026644(param_1,param_3,iVar2,iVar5,param_4);
    if (iVar2 != 0) {
      return 0xffffffff;
    }
    uVar1 = *(ushort *)(param_3 + 3);
    iVar5 = (int)(short)uVar1;
    uVar3 = param_3[0x19];
  }
  if (iVar5 << 0x12 < 0) {
    if (-1 < (int)(uVar3 << 0x12)) {
      return 0xffffffff;
    }
  }
  else {
    *(ushort *)(param_3 + 3) = uVar1 | 0x2000;
    param_3[0x19] = uVar3 | 0x2000;
  }
  uVar3 = (uint)param_2;
  pbVar4 = (byte *)*param_3;
  if ((int)pbVar4 - param_3[4] < (int)param_3[5]) {
    iVar2 = ((int)pbVar4 - param_3[4]) + 1;
  }
  else {
    iVar2 = FUN_08025d30(param_1,param_3);
    if (iVar2 != 0) {
      return 0xffffffff;
    }
    pbVar4 = (byte *)*param_3;
    iVar2 = 1;
  }
  param_3[2] = param_3[2] + -1;
  *param_3 = pbVar4 + 1;
  *pbVar4 = param_2;
  if (param_3[5] != iVar2) {
    if (-1 < (int)((uint)*(ushort *)(param_3 + 3) << 0x1f)) {
      return uVar3;
    }
    if (param_2 != 10) {
      return uVar3;
    }
  }
  iVar2 = FUN_08025d30(param_1,param_3);
  if (iVar2 != 0) {
    return 0xffffffff;
  }
  return uVar3;
}

