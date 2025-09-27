
int * FUN_0800afe8(int *param_1,int param_2,uint param_3)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  
  piVar3 = param_1;
  iVar2 = param_2;
  uVar4 = param_3;
  uVar1 = FUN_0800acd4();
  FUN_0800ad00(param_1,uVar1,param_3,DAT_0800b05c,piVar3,iVar2,uVar4);
  iVar2 = FUN_0800ad20(param_1,param_2);
  if ((iVar2 == 0) && (iVar2 = *param_1, *(int *)(iVar2 + -4) < 1)) {
    uVar4 = param_2 - iVar2 >> 2;
    if (uVar4 < param_3) {
      if (uVar4 != 0) {
        FUN_0800ac92(iVar2,param_2,param_3);
      }
    }
    else {
      FUN_0800ac7a(iVar2,param_2,param_3);
    }
    FUN_0800adb8(*param_1 + -0xc,param_3);
  }
  else {
    param_1 = (int *)FUN_0800afc4(param_1,0,uVar1,param_2,param_3);
  }
  return param_1;
}

