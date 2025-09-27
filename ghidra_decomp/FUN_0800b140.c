
int * FUN_0800b140(int *param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  
  if (param_3 != 0) {
    FUN_0800ad00(param_1,0,param_3,DAT_0800b1bc);
    iVar1 = FUN_0800acd4(param_1);
    iVar3 = *param_1;
    uVar2 = iVar1 + param_3;
    if ((*(uint *)(iVar3 + -8) < uVar2) || (0 < *(int *)(iVar3 + -4))) {
      iVar1 = FUN_0800ad20(param_1,param_2);
      if (iVar1 == 0) {
        FUN_0800b0a6(param_1,uVar2);
        param_2 = *param_1 + (param_2 - iVar3);
      }
      else {
        FUN_0800b0a6(param_1,uVar2);
      }
    }
    iVar1 = FUN_0800acd4(param_1);
    FUN_0800ac7a(*param_1 + iVar1 * 4,param_2,param_3);
    FUN_0800adb8(*param_1 + -0xc,uVar2);
  }
  return param_1;
}

