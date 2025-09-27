
uint FUN_08025ae4(uint param_1)

{
  if ((param_1 < 0xff) && ((*(byte *)(DAT_08025af8 + param_1) & 3) == 1)) {
    param_1 = param_1 + 0x20;
  }
  return param_1;
}

