
undefined4 FUN_08008438(void)

{
  code *pcVar1;
  
  FUN_08008428();
  pcVar1 = (code *)FUN_08008420();
  (*pcVar1)();
  FUN_08008438();
  DataMemoryBarrier(0x1b);
  return *DAT_08008458;
}

