
void FUN_0801e738(undefined4 *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  undefined4 uVar2;
  
  if (param_2 == 0) {
    iVar1 = -4;
  }
  else {
    iVar1 = FUN_0802698c(param_2);
    iVar1 = param_2 + iVar1 * 4;
  }
  uVar2 = FUN_0801e62c(param_2,iVar1,param_3);
  *param_1 = uVar2;
  return;
}

