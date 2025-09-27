
uint FUN_08025ef4(int param_1,uint param_2,uint param_3,uint param_4,int *param_5)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  uint uVar9;
  
  uVar3 = param_4 * param_3;
  if (uVar3 != 0) {
    iVar7 = param_1;
    uVar8 = param_2;
    uVar9 = param_3;
    if ((param_1 != 0) && (*(int *)(param_1 + 0x20) == 0)) {
      FUN_08025ec4();
    }
    if ((-1 < param_5[0x19] << 0x1f) && (-1 < (int)((uint)*(ushort *)(param_5 + 3) << 0x16))) {
      FUN_08028650(param_5[0x16]);
    }
    uVar4 = param_5[1];
    uVar1 = uVar3;
    if ((int)uVar4 < 0) {
      uVar4 = 0;
      param_5[1] = 0;
    }
    do {
      uVar6 = uVar1;
      uVar5 = param_5[1];
      if (uVar6 <= uVar5) {
        FUN_08028666(param_2,*param_5,uVar6,uVar4,iVar7,uVar8,uVar9);
        param_5[1] = param_5[1] - uVar6;
        *param_5 = *param_5 + uVar6;
        if (param_5[0x19] << 0x1f < 0) {
          return param_4;
        }
        if ((int)((uint)*(ushort *)(param_5 + 3) << 0x16) < 0) {
          return param_4;
        }
        FUN_08028654(param_5[0x16]);
        return param_4;
      }
      FUN_08028666(param_2,*param_5,uVar5,uVar4,iVar7,uVar8,uVar9);
      *param_5 = *param_5 + uVar5;
      uVar4 = uVar6 - uVar5;
      iVar2 = FUN_080261d0(param_1,param_5);
      param_2 = param_2 + uVar5;
      uVar1 = uVar4;
      uVar8 = uVar4;
    } while (iVar2 == 0);
    if ((-1 < param_5[0x19] << 0x1f) && (-1 < (int)((uint)*(ushort *)(param_5 + 3) << 0x16))) {
      FUN_08028654(param_5[0x16]);
    }
    uVar3 = ((uVar5 + uVar3) - uVar6) / param_3;
  }
  return uVar3;
}

