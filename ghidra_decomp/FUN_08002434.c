
undefined4 FUN_08002434(int *param_1,undefined4 param_2)

{
  int iVar1;
  int local_1c;
  
  iVar1 = FUN_08002374(param_1,2,1,param_2);
  if (iVar1 != 0) {
LAB_08002494:
    param_1[0x15] = param_1[0x15] | 0x20;
    return 3;
  }
  local_1c = (uint)((ulonglong)DAT_080024a8 * (ulonglong)*DAT_080024a4 >> 0x35) * 1000;
  if (param_1[1] == 0x104) {
    iVar1 = FUN_08002374(param_1,0x80,0,param_2);
    if (iVar1 != 0) goto LAB_08002494;
  }
  else {
    do {
      if (local_1c == 0) {
        return 0;
      }
      local_1c = local_1c + -1;
    } while (*(int *)(*param_1 + 8) << 0x18 < 0);
  }
  return 0;
}

