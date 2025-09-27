
undefined4
FUN_08026644(undefined4 *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  ushort uVar2;
  uint uVar3;
  
  if ((*DAT_080266e8 != 0) && (*(int *)(*DAT_080266e8 + 0x20) == 0)) {
    FUN_08025ec4();
  }
  uVar2 = *(ushort *)(param_2 + 3);
  uVar3 = (uint)(short)uVar2;
  if (-1 < (int)(uVar3 << 0x1c)) {
    if (-1 < (int)(uVar3 << 0x1b)) {
      *param_1 = 9;
      goto LAB_08026668;
    }
    if ((int)(uVar3 << 0x1d) < 0) {
      if ((undefined4 *)param_2[0xd] != (undefined4 *)0x0) {
        if ((undefined4 *)param_2[0xd] != param_2 + 0x11) {
          FUN_08028790(param_1);
        }
        param_2[0xd] = 0;
      }
      param_2[1] = 0;
      *param_2 = param_2[4];
      uVar3 = (int)*(short *)(param_2 + 3) & 0xffffffdb;
    }
    uVar3 = uVar3 | 8;
    *(short *)(param_2 + 3) = (short)uVar3;
  }
  if ((param_2[4] == 0) && ((uVar3 & 0x280) != 0x200)) {
    FUN_0802a848(param_1,param_2,0,uVar3 & 0x280,param_4);
  }
  uVar2 = *(ushort *)(param_2 + 3);
  uVar3 = (uint)(short)uVar2;
  if ((uVar3 & 1) == 0) {
    uVar1 = 0;
    if (-1 < (int)(uVar3 << 0x1e)) {
      uVar1 = param_2[5];
    }
    param_2[2] = uVar1;
  }
  else {
    param_2[2] = 0;
    param_2[6] = -param_2[5];
  }
  if (param_2[4] != 0) {
    return 0;
  }
  if ((uVar3 & 0x80) == 0) {
    return 0;
  }
LAB_08026668:
  *(ushort *)(param_2 + 3) = uVar2 | 0x40;
  return 0xffffffff;
}

