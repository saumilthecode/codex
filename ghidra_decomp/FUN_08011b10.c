
void FUN_08011b10(undefined4 *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_2 == 0) {
    iVar1 = -1;
  }
  else {
    iVar1 = FUN_08005ea0(param_2);
    iVar1 = param_2 + iVar1;
  }
  uVar2 = FUN_08011a24(param_2,iVar1,param_3);
  *param_1 = uVar2;
  return;
}

