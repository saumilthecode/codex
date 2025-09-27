
undefined4 FUN_080261d0(undefined4 *param_1,undefined4 *param_2)

{
  undefined4 uVar1;
  undefined4 uVar2;
  undefined4 uVar3;
  ushort uVar4;
  int iVar5;
  
  if ((param_1 != (undefined4 *)0x0) && (param_1[8] == 0)) {
    FUN_08025ec4();
  }
  param_2[1] = 0;
  uVar4 = *(ushort *)(param_2 + 3);
  iVar5 = (int)(short)uVar4;
  if (iVar5 << 0x1a < 0) {
    return 0xffffffff;
  }
  if (iVar5 << 0x1d < 0) {
    if ((undefined4 *)param_2[0xd] != (undefined4 *)0x0) {
      if ((undefined4 *)param_2[0xd] != param_2 + 0x11) {
        FUN_08028790(param_1);
      }
      param_2[0xd] = 0;
      param_2[1] = param_2[0x10];
      if (param_2[0x10] != 0) {
        *param_2 = param_2[0xf];
        return 0;
      }
    }
LAB_08026226:
    if (param_2[4] == 0) {
      FUN_0802a848(param_1,param_2);
    }
    uVar3 = DAT_080262b0;
    uVar2 = DAT_080262ac;
    uVar1 = DAT_080262a8;
    uVar4 = *(ushort *)(param_2 + 3);
    if ((uVar4 & 3) != 0) {
      *(undefined2 *)(param_2 + 3) = 1;
      FUN_08025fec(uVar3,uVar2,uVar1);
      *(ushort *)(param_2 + 3) = uVar4;
      if ((uVar4 & 9) == 9) {
        FUN_08025c34(param_1,param_2);
      }
    }
    *param_2 = param_2[4];
    iVar5 = (*(code *)param_2[9])(param_1,param_2[8],param_2[4],param_2[5]);
    param_2[1] = iVar5;
    if (0 < iVar5) {
      return 0;
    }
    uVar4 = *(ushort *)(param_2 + 3);
    if (iVar5 == 0) {
      uVar4 = uVar4 | 0x20;
      goto LAB_080261fc;
    }
    param_2[1] = 0;
  }
  else {
    if (iVar5 << 0x1b < 0) {
      if (iVar5 << 0x1c < 0) {
        iVar5 = FUN_08025d30(param_1,param_2);
        if (iVar5 != 0) {
          return 0xffffffff;
        }
        param_2[2] = 0;
        uVar4 = *(ushort *)(param_2 + 3) & 0xfff7;
        param_2[6] = 0;
      }
      *(ushort *)(param_2 + 3) = uVar4 | 4;
      goto LAB_08026226;
    }
    *param_1 = 9;
  }
  uVar4 = uVar4 | 0x40;
LAB_080261fc:
  *(ushort *)(param_2 + 3) = uVar4;
  return 0xffffffff;
}

