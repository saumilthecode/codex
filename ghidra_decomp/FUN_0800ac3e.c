
void FUN_0800ac3e(int *param_1,undefined1 param_2,undefined4 param_3,undefined4 param_4)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar2 = FUN_0800a648();
  iVar3 = *param_1;
  puVar1 = (uint *)(iVar3 + -8);
  uVar4 = iVar2 + 1;
  if ((*puVar1 < uVar4) || (iVar3 = *(int *)(iVar3 + -4), 0 < iVar3)) {
    FUN_0800aa82(param_1,uVar4,*puVar1,iVar3,param_4);
  }
  iVar2 = FUN_0800a648(param_1);
  *(undefined1 *)(*param_1 + iVar2) = param_2;
  FUN_0800a74c(*param_1 + -0xc,uVar4);
  return;
}

