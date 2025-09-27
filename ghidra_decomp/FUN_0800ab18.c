
int * FUN_0800ab18(int *param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  if (param_3 != 0) {
    FUN_0800a674(param_1,0,param_3,DAT_0800ab90);
    iVar1 = FUN_0800a648(param_1);
    iVar3 = *param_1;
    uVar2 = iVar1 + param_3;
    if ((*(uint *)(iVar3 + -8) < uVar2) || (0 < *(int *)(iVar3 + -4))) {
      iVar1 = FUN_0800a694(param_1,param_2);
      if (iVar1 == 0) {
        FUN_0800aa82(param_1,uVar2);
        param_2 = *param_1 + (param_2 - iVar3);
      }
      else {
        FUN_0800aa82(param_1,uVar2);
      }
    }
    iVar1 = FUN_0800a648(param_1);
    FUN_0800a5f0(iVar1 + *param_1,param_2,param_3);
    FUN_0800a74c(*param_1 + -0xc,uVar2);
  }
  return param_1;
}

