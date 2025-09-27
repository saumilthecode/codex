
int * FUN_0800b0e4(int *param_1,undefined4 *param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  
  iVar1 = FUN_0800acd4(param_2);
  if (iVar1 != 0) {
    iVar2 = FUN_0800acd4(param_1);
    uVar3 = iVar2 + iVar1;
    if ((*(uint *)(*param_1 + -8) < uVar3) || (0 < *(int *)(*param_1 + -4))) {
      FUN_0800b0a6(param_1,uVar3);
    }
    iVar2 = FUN_0800acd4(param_1);
    FUN_0800ac7a(*param_1 + iVar2 * 4,*param_2,iVar1);
    FUN_0800adb8(*param_1 + -0xc,uVar3);
  }
  return param_1;
}

