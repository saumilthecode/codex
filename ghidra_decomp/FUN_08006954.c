
undefined4 FUN_08006954(uint param_1,uint param_2)

{
  if ((((int)(param_1 << 1) >> 0x18 != -1) || ((param_1 & 0x7fffff) == 0)) &&
     (((int)(param_2 << 1) >> 0x18 != -1 || ((param_2 & 0x7fffff) == 0)))) {
    return 0;
  }
  return 1;
}

