
undefined4 FUN_080005d0(void)

{
  uint *puVar1;
  
  puVar1 = DAT_08000600;
  *DAT_08000600 = *DAT_08000600 | 0x200;
  *puVar1 = *puVar1 | 0x400;
  *puVar1 = *puVar1 | 0x100;
  FUN_08000770(3);
  FUN_0800058c(0xf);
  FUN_08000548();
  return 0;
}

