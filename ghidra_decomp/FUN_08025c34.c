
undefined4 FUN_08025c34(uint *param_1,int *param_2,undefined4 param_3,undefined4 param_4)

{
  int *piVar1;
  uint uVar2;
  int iVar3;
  ushort uVar4;
  int iVar5;
  code *pcVar6;
  int iVar7;
  uint uVar8;
  bool bVar9;
  
  uVar2 = (uint)(short)param_2[3];
  if ((int)(uVar2 << 0x1c) < 0) {
    iVar3 = param_2[4];
    if (iVar3 != 0) {
      iVar5 = uVar2 << 0x1e;
      bVar9 = iVar5 == 0;
      iVar7 = *param_2;
      if (bVar9) {
        iVar5 = param_2[5];
      }
      *param_2 = iVar3;
      if (!bVar9) {
        iVar5 = 0;
      }
      param_2[2] = iVar5;
      for (iVar7 = iVar7 - iVar3; 0 < iVar7; iVar7 = iVar7 - iVar5) {
        iVar5 = (*(code *)param_2[10])(param_1,param_2[8],iVar3,iVar7,param_4);
        if (iVar5 < 1) goto LAB_08025d14;
        iVar3 = iVar3 + iVar5;
      }
    }
  }
  else {
    if ((param_2[1] < 1) && (param_2[0x10] < 1)) {
      return 0;
    }
    pcVar6 = (code *)param_2[0xb];
    if (pcVar6 == (code *)0x0) {
      return 0;
    }
    uVar8 = *param_1;
    *param_1 = 0;
    if ((uVar2 & 0x1000) == 0) {
      iVar3 = (*pcVar6)(param_1,param_2[8],0,1);
      if ((iVar3 == -1) && (uVar2 = *param_1, uVar2 != 0)) {
        if ((uVar2 == 0x1d) || (uVar2 == 0x16)) {
          *param_1 = uVar8;
          return 0;
        }
LAB_08025d14:
        uVar4 = *(ushort *)(param_2 + 3);
        goto LAB_08025d18;
      }
    }
    else {
      iVar3 = param_2[0x15];
    }
    if (((int)((uint)*(ushort *)(param_2 + 3) << 0x1d) < 0) &&
       (iVar3 = iVar3 - param_2[1], param_2[0xd] != 0)) {
      iVar3 = iVar3 - param_2[0x10];
    }
    iVar3 = (*(code *)param_2[0xb])(param_1,param_2[8],iVar3,0);
    uVar4 = *(ushort *)(param_2 + 3);
    if ((iVar3 == -1) &&
       ((0x1d < *param_1 || (-1 < (int)((DAT_08025d2c >> (*param_1 & 0xff)) << 0x1f))))) {
LAB_08025d18:
      *(ushort *)(param_2 + 3) = uVar4 | 0x40;
      return 0xffffffff;
    }
    param_2[1] = 0;
    *param_2 = param_2[4];
    if (((int)(short)uVar4 << 0x13 < 0) && ((iVar3 != -1 || (*param_1 == 0)))) {
      param_2[0x15] = iVar3;
    }
    piVar1 = (int *)param_2[0xd];
    *param_1 = uVar8;
    if (piVar1 != (int *)0x0) {
      if (piVar1 != param_2 + 0x11) {
        FUN_08028790(param_1);
      }
      param_2[0xd] = 0;
    }
  }
  return 0;
}

