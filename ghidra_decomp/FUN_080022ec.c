
undefined4 FUN_080022ec(int *param_1,undefined4 param_2,undefined4 param_3)

{
  int iVar1;
  int local_1c;
  
  iVar1 = FUN_08002214(param_1,2,1,param_2,param_3);
  if (iVar1 != 0) {
LAB_08002358:
    param_1[0x15] = param_1[0x15] | 0x20;
    return 3;
  }
  local_1c = (uint)((ulonglong)DAT_08002370 * (ulonglong)*DAT_0800236c >> 0x35) * 1000;
  if (param_1[1] == 0x104) {
    iVar1 = FUN_08002214(param_1,0x80,0,param_2,param_3);
    if (iVar1 != 0) goto LAB_08002358;
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

