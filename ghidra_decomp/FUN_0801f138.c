
uint FUN_0801f138(int param_1,int param_2,int *param_3,undefined4 param_4,int *param_5)

{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  if ((param_3 == param_5) &&
     (iVar4 = FUN_08008590(param_1,param_4,param_3,param_4,param_1,param_2,param_3), iVar4 != 0)) {
    uVar1 = 6;
  }
  else {
    iVar4 = *(int *)(param_1 + 0xc);
    param_1 = param_1 + iVar4 * 8;
    for (; iVar4 != 0; iVar4 = iVar4 + -1) {
      uVar1 = *(uint *)(param_1 + 0xc);
      if ((int)(uVar1 << 0x1e) < 0) {
        iVar3 = (int)uVar1 >> 8;
        if ((uVar1 & 1) != 0) {
          if (param_2 == -3) goto LAB_0801f1a0;
          iVar3 = *(int *)(*param_3 + iVar3);
        }
        uVar2 = (**(code **)(**(int **)(param_1 + 8) + 0x20))
                          (*(int **)(param_1 + 8),param_2,iVar3 + (int)param_3,param_4,param_5);
        if (3 < uVar2) {
          return uVar2 & 0xff | uVar1 & 1;
        }
      }
LAB_0801f1a0:
      param_1 = param_1 + -8;
    }
    uVar1 = 1;
  }
  return uVar1;
}

