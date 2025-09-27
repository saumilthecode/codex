
void FUN_08020a34(int param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  undefined4 uVar1;
  int iVar2;
  undefined4 uVar3;
  
  uVar1 = FUN_08028514(0);
  iVar2 = FUN_08005ea0();
  uVar3 = thunk_FUN_08008466(iVar2 + 1);
  FUN_08028666(uVar3,uVar1,iVar2 + 1);
  FUN_08028514(0,*(undefined4 *)(param_1 + 0x10));
  iVar2 = thunk_FUN_08027a74(param_2,param_3,param_4,param_5);
  FUN_08028514(0,uVar3);
  thunk_FUN_080249c4(uVar3);
  if (iVar2 == 0) {
    *param_2 = 0;
  }
  return;
}

