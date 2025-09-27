
int * FUN_0800a9cc(int *param_1,int param_2,uint param_3)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  
  piVar3 = param_1;
  iVar2 = param_2;
  uVar4 = param_3;
  uVar1 = FUN_0800a648();
  FUN_0800a674(param_1,uVar1,param_3,DAT_0800aa38,piVar3,iVar2,uVar4);
  iVar2 = FUN_0800a694(param_1,param_2);
  if ((iVar2 == 0) && (iVar2 = *param_1, *(int *)(iVar2 + -4) < 1)) {
    if ((uint)(param_2 - iVar2) < param_3) {
      if (param_2 != iVar2) {
        FUN_0800a608(iVar2,param_2,param_3);
      }
    }
    else {
      FUN_0800a5f0(iVar2,param_2,param_3);
    }
    FUN_0800a74c(*param_1 + -0xc,param_3);
  }
  else {
    param_1 = (int *)FUN_0800a9a8(param_1,0,uVar1,param_2,param_3);
  }
  return param_1;
}

