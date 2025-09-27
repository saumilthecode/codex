
undefined4 FUN_08019070(int *param_1)

{
  uint uVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar1 = FUN_08008a40(DAT_0801909c);
  if ((uVar1 < *(uint *)(*param_1 + 8)) &&
     (iVar2 = *(int *)(*(int *)(*param_1 + 4) + uVar1 * 4), iVar2 != 0)) {
    uVar3 = FUN_0801ef04(iVar2,DAT_080190a4,DAT_080190a0,0);
    return uVar3;
  }
  return 0;
}

