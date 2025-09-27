
uint FUN_080265c8(int param_1,byte param_2,int *param_3,undefined4 param_4)

{
  int iVar1;
  uint uVar2;
  byte *pbVar3;
  
  if ((param_1 != 0) && (*(int *)(param_1 + 0x20) == 0)) {
    FUN_08025ec4();
  }
  param_3[2] = param_3[6];
  uVar2 = (uint)*(ushort *)(param_3 + 3);
  iVar1 = uVar2 << 0x1c;
  if (((iVar1 < 0) && (uVar2 = param_3[4], uVar2 != 0)) ||
     (iVar1 = FUN_08026644(param_1,param_3,iVar1,uVar2,param_4), iVar1 == 0)) {
    iVar1 = *param_3 - param_3[4];
    uVar2 = (uint)param_2;
    if ((iVar1 < param_3[5]) || (iVar1 = FUN_08025d30(param_1,param_3), iVar1 == 0)) {
      param_3[2] = param_3[2] + -1;
      pbVar3 = (byte *)*param_3;
      *param_3 = (int)(pbVar3 + 1);
      *pbVar3 = param_2;
      if (param_3[5] != iVar1 + 1) {
        if (-1 < (int)((uint)*(ushort *)(param_3 + 3) << 0x1f)) {
          return uVar2;
        }
        if (uVar2 != 10) {
          return uVar2;
        }
      }
      iVar1 = FUN_08025d30(param_1,param_3);
      if (iVar1 == 0) {
        return uVar2;
      }
    }
  }
  return 0xffffffff;
}

