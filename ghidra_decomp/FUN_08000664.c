
void FUN_08000664(uint param_1)

{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_0800061c();
  if (param_1 != 0xffffffff) {
    param_1 = param_1 + *DAT_08000684;
  }
  do {
    iVar2 = FUN_0800061c();
  } while ((uint)(iVar2 - iVar1) < param_1);
  return;
}

