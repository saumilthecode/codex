
void FUN_0802c388(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = *DAT_0802c3c0;
  if ((iVar1 != 0) && (*(int *)(iVar1 + 0x34) == 0)) {
    FUN_08025ec4(iVar1,param_2,param_2);
    FUN_0802c2ec(iVar1,param_1,param_2);
    return;
  }
  FUN_0802c2ec(iVar1,param_1);
  return;
}

