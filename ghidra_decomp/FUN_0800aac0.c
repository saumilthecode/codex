
int * FUN_0800aac0(int *param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  iVar1 = FUN_0800a648(param_2);
  if (iVar1 != 0) {
    iVar2 = FUN_0800a648(param_1);
    uVar3 = iVar2 + iVar1;
    if ((*(uint *)(*param_1 + -8) < uVar3) || (0 < *(int *)(*param_1 + -4))) {
      FUN_0800aa82(param_1,uVar3);
    }
    iVar2 = FUN_0800a648(param_1);
    FUN_0800a5f0(iVar2 + *param_1,*param_2,iVar1);
    FUN_0800a74c(*param_1 + -0xc,uVar3);
  }
  return param_1;
}

