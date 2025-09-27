
void FUN_080291e4(undefined4 param_1,undefined4 param_2)

{
  int iVar1;
  
  iVar1 = FUN_08028f6c(param_1,1);
  if (iVar1 == 0) {
    iVar1 = FUN_08028754(DAT_0802920c,0x145,0,DAT_08029208);
  }
  *(undefined4 *)(iVar1 + 0x14) = param_2;
  *(undefined4 *)(iVar1 + 0x10) = 1;
  return;
}

