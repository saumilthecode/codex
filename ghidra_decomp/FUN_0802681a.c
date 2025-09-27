
int FUN_0802681a(undefined4 *param_1,int *param_2)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  
  if ((param_1 != (undefined4 *)0x0) && (param_1[8] == 0)) {
    FUN_08025ec4();
  }
  if ((-1 < param_2[0x19] << 0x1f) && (-1 < (int)((uint)*(ushort *)(param_2 + 3) << 0x16))) {
    FUN_08028650(param_2[0x16]);
  }
  if ((code *)param_2[0xb] == (code *)0x0) {
    *param_1 = 0x1d;
LAB_08026844:
    if ((-1 < param_2[0x19] << 0x1f) && (-1 < (int)((uint)*(ushort *)(param_2 + 3) << 0x16))) {
      FUN_08028654(param_2[0x16]);
    }
    iVar4 = -1;
  }
  else {
    uVar1 = (uint)(short)param_2[3];
    if (((((uVar1 & 0xc) == 8) && (*param_2 != 0)) && (0 < *param_2 - param_2[4])) &&
       ((int)(uVar1 << 0x17) < 0)) {
      uVar3 = 2;
LAB_0802687e:
      iVar4 = (*(code *)param_2[0xb])(param_1,param_2[8],0,uVar3);
      if (iVar4 == -1) goto LAB_08026844;
    }
    else {
      if ((uVar1 & 0x1000) == 0) {
        uVar3 = 1;
        goto LAB_0802687e;
      }
      iVar4 = param_2[0x15];
    }
    iVar2 = (int)(short)param_2[3];
    if (iVar2 << 0x1d < 0) {
      iVar4 = iVar4 - param_2[1];
      if (param_2[0xd] != 0) {
        iVar4 = iVar4 - param_2[0x10];
      }
    }
    else if ((iVar2 << 0x1c < 0) && (*param_2 != 0)) {
      iVar4 = iVar4 + (*param_2 - param_2[4]);
    }
    if ((-1 < param_2[0x19] << 0x1f) && (-1 < iVar2 << 0x16)) {
      FUN_08028654(param_2[0x16]);
    }
  }
  return iVar4;
}

