
void FUN_0800b26e(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  uint *puVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  
  iVar2 = FUN_0800acd4();
  iVar3 = *param_1;
  puVar1 = (uint *)(iVar3 + -8);
  uVar4 = iVar2 + 1;
  if ((*puVar1 < uVar4) || (iVar3 = *(int *)(iVar3 + -4), 0 < iVar3)) {
    FUN_0800b0a6(param_1,uVar4,*puVar1,iVar3,param_4);
  }
  iVar2 = FUN_0800acd4(param_1);
  iVar3 = *param_1;
  *(undefined4 *)(iVar3 + iVar2 * 4) = param_2;
  FUN_0800adb8(iVar3 + -0xc,uVar4);
  return;
}

