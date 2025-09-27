
undefined4 FUN_08029bc0(undefined4 *param_1,int *param_2,undefined4 param_3,uint param_4)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  
  uVar3 = param_4;
  if (((uint)param_2[2] <= param_4) && (uVar3 = param_2[2], ((int)(short)param_2[3] & 0x480U) != 0))
  {
    iVar4 = *param_2 - param_2[4];
    uVar3 = (param_2[5] * 3) / 2;
    uVar2 = param_4 + 1 + iVar4;
    if (uVar3 < uVar2) {
      uVar3 = uVar2;
    }
    if ((int)(short)param_2[3] << 0x15 < 0) {
      iVar1 = FUN_08024a18(param_1,uVar3);
      if (iVar1 == 0) {
LAB_08029c68:
        *param_1 = 0xc;
        *(ushort *)(param_2 + 3) = *(ushort *)(param_2 + 3) | 0x40;
        return 0xffffffff;
      }
      FUN_08028666(iVar1,param_2[4],iVar4);
      *(ushort *)(param_2 + 3) = *(ushort *)(param_2 + 3) & 0xfb7f | 0x80;
    }
    else {
      iVar1 = FUN_080298c8(param_1);
      if (iVar1 == 0) {
        FUN_08028790(param_1,param_2[4]);
        goto LAB_08029c68;
      }
    }
    param_2[4] = iVar1;
    param_2[5] = uVar3;
    *param_2 = iVar1 + iVar4;
    param_2[2] = uVar3 - iVar4;
    uVar3 = param_4;
  }
  FUN_080268f0(*param_2,param_3,uVar3);
  param_2[2] = param_2[2] - uVar3;
  *param_2 = *param_2 + uVar3;
  return 0;
}

