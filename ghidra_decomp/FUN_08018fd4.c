
undefined4 FUN_08018fd4(int *param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar1 = FUN_08008a40(DAT_0801901c);
  iVar3 = *(int *)(*param_1 + 0xc);
  if (*(int *)(iVar3 + iVar1 * 4) == 0) {
    uVar2 = FUN_08008466(0x128);
    FUN_08018ba0(uVar2,0);
    FUN_08018ec4(uVar2,param_1);
    FUN_08008bb0(*param_1,uVar2,iVar1);
  }
  return *(undefined4 *)(iVar3 + iVar1 * 4);
}

