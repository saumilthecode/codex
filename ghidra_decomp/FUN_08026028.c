
uint FUN_08026028(int param_1,int param_2,uint param_3,int param_4,undefined4 *param_5)

{
  char cVar1;
  char *pcVar2;
  uint uVar3;
  int iVar4;
  
  if ((param_1 != 0) && (*(int *)(param_1 + 0x20) == 0)) {
    FUN_08025ec4();
  }
  if ((-1 < (int)(param_5[0x19] << 0x1f)) && (-1 < (int)((uint)*(ushort *)(param_5 + 3) << 0x16))) {
    FUN_08028650(param_5[0x16]);
  }
  if ((((int)((uint)*(ushort *)(param_5 + 3) << 0x1c) < 0) && (param_5[4] != 0)) ||
     (iVar4 = FUN_08026644(param_1,param_5), iVar4 == 0)) {
    for (uVar3 = 0; uVar3 != param_3 * param_4; uVar3 = uVar3 + 1) {
      cVar1 = *(char *)(param_2 + uVar3);
      iVar4 = param_5[2] + -1;
      param_5[2] = iVar4;
      if ((iVar4 < 0) && ((iVar4 < (int)param_5[6] || (cVar1 == '\n')))) {
        iVar4 = FUN_080265c8(param_1,cVar1,param_5);
        if (iVar4 == -1) break;
      }
      else {
        pcVar2 = (char *)*param_5;
        *param_5 = pcVar2 + 1;
        *pcVar2 = cVar1;
      }
    }
  }
  else {
    uVar3 = 0;
  }
  if ((-1 < (int)(param_5[0x19] << 0x1f)) && (-1 < (int)((uint)*(ushort *)(param_5 + 3) << 0x16))) {
    FUN_08028654(param_5[0x16]);
  }
  return uVar3 / param_3;
}

