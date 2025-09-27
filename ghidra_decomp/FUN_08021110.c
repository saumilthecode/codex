
undefined4 FUN_08021110(int *param_1,undefined4 param_2,uint param_3,undefined4 param_4,int param_5)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  ushort *puVar5;
  
  iVar1 = FUN_080210e4(param_2,param_4);
  if (iVar1 == 0) {
LAB_08021126:
    uVar2 = 1;
  }
  else {
    while( true ) {
      puVar5 = (ushort *)*param_1;
      if ((ushort *)param_1[1] == puVar5) break;
      uVar4 = (uint)*puVar5;
      if (uVar4 - 0xd800 < 0x400) {
        if (param_5 == 1) {
          return 2;
        }
        if ((uint)(param_1[1] - (int)puVar5) < 3) goto LAB_08021126;
        if (0x3ff < puVar5[1] - 0xdc00) {
          return 2;
        }
        uVar4 = puVar5[1] + 0xfca02400 + uVar4 * 0x400;
        iVar1 = 2;
      }
      else {
        if (uVar4 - 0xdc00 < 0x400) {
          return 2;
        }
        iVar1 = 1;
      }
      if (param_3 < uVar4) {
        return 2;
      }
      iVar3 = FUN_08020cac(param_2);
      if (iVar3 == 0) goto LAB_08021126;
      *param_1 = *param_1 + iVar1 * 2;
    }
    uVar2 = 0;
  }
  return uVar2;
}

