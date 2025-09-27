
undefined4 FUN_0800d708(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  
  uVar1 = FUN_08028514(4,0,param_3,param_4,param_1,param_2,param_3);
  iVar2 = FUN_08005de4(uVar1,DAT_0800d774);
  if (iVar2 != 0) {
    iVar3 = FUN_08005ea0(uVar1);
    iVar2 = thunk_FUN_08008466(iVar3 + 1);
    FUN_08028666(iVar2,uVar1,iVar3 + 1);
    FUN_08028514(4,DAT_0800d774);
  }
  uVar1 = FUN_080265ac(param_2,param_3,param_4,&stack0x00000000,param_1,&stack0x00000000);
  if (iVar2 != 0) {
    FUN_08028514(4,iVar2);
    thunk_FUN_080249c4(iVar2);
  }
  return uVar1;
}

