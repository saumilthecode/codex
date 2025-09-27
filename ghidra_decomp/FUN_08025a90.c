
byte FUN_08025a90(uint param_1)

{
  byte bVar1;
  
  if (param_1 < 0x100) {
    bVar1 = *(byte *)(DAT_08025aa0 + param_1) & 8;
  }
  else {
    bVar1 = 0;
  }
  return bVar1;
}

