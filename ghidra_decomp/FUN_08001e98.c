
uint FUN_08001e98(void)

{
  return *DAT_08001eb0 >>
         *(sbyte *)(DAT_08001eb4 + ((uint)(*(int *)(DAT_08001eac + 8) << 0x10) >> 0x1d));
}

