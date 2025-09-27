
uint FUN_08025afc(uint param_1)

{
  if ((param_1 < 0xff) && ((*(byte *)(DAT_08025b10 + param_1) & 3) == 2)) {
    param_1 = param_1 - 0x20;
  }
  return param_1;
}

