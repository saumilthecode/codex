
void FUN_0801f688(undefined4 param_1,undefined4 *param_2,undefined4 *param_3)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  
  iVar1 = FUN_0801f54c();
  if (iVar1 == 0) {
    *param_3 = 4;
    return;
  }
  iVar2 = FUN_080262e4(param_1,DAT_0801f704,param_2);
  if (iVar2 + 1U < 2) {
    uVar3 = 0;
    uVar4 = 0;
  }
  else {
    uVar3 = *param_2;
    uVar4 = param_2[1];
    iVar2 = FUN_080066f8(uVar3,uVar4,0,DAT_0801f708);
    if (iVar2 == 0) {
      iVar2 = FUN_080066f8(uVar3,uVar4,0,DAT_0801f70c);
      if (iVar2 == 0) goto LAB_0801f6be;
      uVar3 = 0xffffffff;
      uVar4 = 0xffefffff;
    }
    else {
      uVar3 = 0xffffffff;
      uVar4 = DAT_0801f710;
    }
  }
  *param_2 = uVar3;
  param_2[1] = uVar4;
  *param_3 = 4;
LAB_0801f6be:
  FUN_08028514(0,iVar1);
  thunk_FUN_080249c4(iVar1);
  return;
}

