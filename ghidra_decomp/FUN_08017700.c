
undefined1 * FUN_08017700(undefined1 *param_1,int *param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  
  *param_1 = 0;
  iVar1 = *param_2;
  *(int **)(param_1 + 4) = param_2;
  if ((*(int *)((int)param_2 + *(int *)(iVar1 + -0xc) + 0x70) != 0) &&
     (*(int *)((int)param_2 + *(int *)(iVar1 + -0xc) + 0x14) == 0)) {
    FUN_080176b6();
  }
  iVar1 = *(int *)(*param_2 + -0xc) + (int)param_2;
  iVar2 = *(int *)(iVar1 + 0x14);
  if (iVar2 == 0) {
    *param_1 = 1;
  }
  else {
    iVar2 = iVar2 << 0x1f;
    if (iVar2 < 0) {
      FUN_08010584(iVar1,4,param_3,iVar2,param_4);
    }
  }
  return param_1;
}

