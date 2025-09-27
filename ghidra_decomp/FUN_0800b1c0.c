
int * FUN_0800b1c0(int *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  uint uVar2;
  
  if (param_2 != 0) {
    FUN_0800ad00(param_1,0,param_2,DAT_0800b220);
    iVar1 = FUN_0800acd4(param_1);
    uVar2 = iVar1 + param_2;
    if ((*(uint *)(*param_1 + -8) < uVar2) || (0 < *(int *)(*param_1 + -4))) {
      FUN_0800b0a6(param_1,uVar2);
    }
    iVar1 = FUN_0800acd4(param_1);
    FUN_0800acaa(*param_1 + iVar1 * 4,param_2,param_3);
    FUN_0800adb8(*param_1 + -0xc,uVar2);
  }
  return param_1;
}

