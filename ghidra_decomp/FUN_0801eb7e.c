
void FUN_0801eb7e(int *param_1,undefined4 param_2,undefined4 param_3)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  iVar2 = param_1[1];
  uVar3 = param_2;
  uVar1 = FUN_0801eac4();
  if (uVar1 < iVar2 + 1U) {
    FUN_0801ead6(param_1,iVar2,0,0,1,uVar3,param_3);
  }
  *(undefined4 *)(*param_1 + iVar2 * 4) = param_2;
  FUN_0801e978(param_1,iVar2 + 1U);
  return;
}

