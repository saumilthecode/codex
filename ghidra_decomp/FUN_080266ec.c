
undefined4 FUN_080266ec(undefined4 *param_1,int *param_2,int param_3,uint param_4)

{
  int iVar1;
  undefined4 uVar2;
  code *pcVar3;
  
  if ((param_1 != (undefined4 *)0x0) && (param_1[8] == 0)) {
    FUN_08025ec4();
  }
  if ((-1 < param_2[0x19] << 0x1f) && (-1 < (int)((uint)*(ushort *)(param_2 + 3) << 0x16))) {
    FUN_08028650(param_2[0x16]);
  }
  if ((*(ushort *)(param_2 + 3) & 0x108) == 0x108) {
    FUN_08025d30(param_1,param_2);
  }
  pcVar3 = (code *)param_2[0xb];
  if (pcVar3 == (code *)0x0) {
    uVar2 = 0x1d;
LAB_08026734:
    *param_1 = uVar2;
  }
  else {
    if (param_4 == 1) {
      FUN_08025d30(param_1,param_2);
      if ((*(ushort *)(param_2 + 3) & 0x1000) == 0) {
        iVar1 = (*pcVar3)(param_1,param_2[8],*(ushort *)(param_2 + 3) & 0x1000,1);
        if (iVar1 == -1) goto LAB_080267ea;
      }
      else {
        iVar1 = param_2[0x15];
      }
      if ((int)(short)param_2[3] << 0x1d < 0) {
        iVar1 = iVar1 - param_2[1];
        if (param_2[0xd] != 0) {
          iVar1 = iVar1 - param_2[0x10];
        }
      }
      else if (((int)(short)param_2[3] << 0x1c < 0) && (*param_2 != 0)) {
        iVar1 = iVar1 + (*param_2 - param_2[4]);
      }
      param_3 = param_3 + iVar1;
      param_4 = 0;
    }
    else if ((param_4 & 0xfffffffd) != 0) {
      uVar2 = 0x16;
      goto LAB_08026734;
    }
    if (param_2[4] == 0) {
      FUN_0802a848(param_1,param_2);
    }
    iVar1 = FUN_08025d30(param_1,param_2);
    if ((iVar1 == 0) && (iVar1 = (*pcVar3)(param_1,param_2[8],param_3,param_4), iVar1 != -1)) {
      if ((int *)param_2[0xd] != (int *)0x0) {
        if ((int *)param_2[0xd] != param_2 + 0x11) {
          FUN_08028790(param_1);
        }
        param_2[0xd] = 0;
      }
      *param_2 = param_2[4];
      *(ushort *)(param_2 + 3) = *(ushort *)(param_2 + 3) & 0xf7df;
      param_2[1] = 0;
      FUN_08026922(param_2 + 0x17,0,8);
      if (param_2[0x19] << 0x1f < 0) {
        return 0;
      }
      if ((int)((uint)*(ushort *)(param_2 + 3) << 0x16) < 0) {
        return 0;
      }
      FUN_08028654(param_2[0x16]);
      return 0;
    }
  }
LAB_080267ea:
  if ((-1 < param_2[0x19] << 0x1f) && (-1 < (int)((uint)*(ushort *)(param_2 + 3) << 0x16))) {
    FUN_08028654(param_2[0x16]);
  }
  return 0xffffffff;
}

