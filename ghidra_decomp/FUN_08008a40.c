
int FUN_08008a40(int *param_1)

{
  int iVar1;
  
  iVar1 = *param_1;
  if (iVar1 == 0) {
    iVar1 = *DAT_08008a54 + 1;
    *DAT_08008a54 = iVar1;
    *param_1 = iVar1;
  }
  return iVar1 + -1;
}

