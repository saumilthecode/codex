
undefined4 FUN_08025d30(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(int *)(param_2 + 0x10) != 0) {
    if ((param_1 != 0) && (*(int *)(param_1 + 0x20) == 0)) {
      FUN_08025ec4();
    }
    if (*(short *)(param_2 + 0xc) != 0) {
      if ((-1 < *(int *)(param_2 + 100) << 0x1f) && (-1 < (int)*(short *)(param_2 + 0xc) << 0x16)) {
        FUN_08028650(*(undefined4 *)(param_2 + 0x58));
      }
      uVar1 = FUN_08025c34(param_1,param_2);
      if (*(int *)(param_2 + 100) << 0x1f < 0) {
        return uVar1;
      }
      if ((int)((uint)*(ushort *)(param_2 + 0xc) << 0x16) < 0) {
        return uVar1;
      }
      FUN_08028654(*(undefined4 *)(param_2 + 0x58));
      return uVar1;
    }
  }
  return 0;
}

