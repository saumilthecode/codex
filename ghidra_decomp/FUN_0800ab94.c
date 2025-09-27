
int * FUN_0800ab94(int *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  uint uVar2;
  
  if (param_2 != 0) {
    FUN_0800a674(param_1,0,param_2,DAT_0800abf0);
    iVar1 = FUN_0800a648(param_1);
    uVar2 = iVar1 + param_2;
    if ((*(uint *)(*param_1 + -8) < uVar2) || (0 < *(int *)(*param_1 + -4))) {
      FUN_0800aa82(param_1,uVar2);
    }
    iVar1 = FUN_0800a648(param_1);
    FUN_0800a620(iVar1 + *param_1,param_2,param_3);
    FUN_0800a74c(*param_1 + -0xc,uVar2);
  }
  return param_1;
}

