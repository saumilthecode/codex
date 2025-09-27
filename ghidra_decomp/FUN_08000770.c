
void FUN_08000770(uint param_1)

{
  *(uint *)(DAT_08000790 + 0xc) =
       (param_1 & 7) << 8 | *(uint *)(DAT_08000790 + 0xc) & 0xf8ff | 0x5fa0000;
  return;
}

