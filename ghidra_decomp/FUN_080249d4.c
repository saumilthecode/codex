
uint FUN_080249d4(undefined4 param_1,undefined4 param_2)

{
  int *piVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  piVar1 = DAT_08024a14;
  if (*DAT_08024a14 == 0) {
    iVar2 = FUN_080285b4();
    *piVar1 = iVar2;
  }
  uVar3 = FUN_080285b4(param_1,param_2);
  if ((uVar3 == 0xffffffff) ||
     ((uVar4 = uVar3 + 3 & 0xfffffffc, uVar3 != uVar4 &&
      (iVar2 = FUN_080285b4(param_1,uVar4 - uVar3), iVar2 == -1)))) {
    uVar4 = 0xffffffff;
  }
  return uVar4;
}

