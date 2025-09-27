
undefined4 FUN_0800ad20(uint *param_1,uint param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  
  uVar3 = *param_1;
  if (param_2 < uVar3) {
    uVar2 = 1;
  }
  else {
    iVar1 = FUN_0800acd4();
    if (uVar3 + iVar1 * 4 < param_2) {
      uVar2 = 1;
    }
    else {
      uVar2 = 0;
    }
  }
  return uVar2;
}

