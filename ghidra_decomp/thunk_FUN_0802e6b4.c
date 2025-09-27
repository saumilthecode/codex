
undefined4 thunk_FUN_0802e6b4(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *DAT_0802e708;
  if ((iVar2 != 0) && (*(int *)(iVar2 + 0x34) == 0)) {
    FUN_08025ec4(iVar2);
  }
  if (-1 < *(int *)(param_2 + 100) << 0x1f) {
    if (-1 < (int)((uint)*(ushort *)(param_2 + 0xc) << 0x16)) {
      FUN_08028650(*(undefined4 *)(param_2 + 0x58));
    }
  }
  uVar1 = FUN_0802e638(iVar2,param_1,param_2);
  if ((-1 < *(int *)(param_2 + 100) << 0x1f) &&
     (-1 < (int)((uint)*(ushort *)(param_2 + 0xc) << 0x16))) {
    FUN_08028654(*(undefined4 *)(param_2 + 0x58));
    return uVar1;
  }
  return uVar1;
}

