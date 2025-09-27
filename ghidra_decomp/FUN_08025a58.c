
byte FUN_08025a58(uint param_1)

{
  byte bVar1;
  
  if (param_1 < 0x100) {
    bVar1 = *(byte *)(DAT_08025a68 + param_1) & 0x97;
  }
  else {
    bVar1 = 0;
  }
  return bVar1;
}

