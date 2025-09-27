
int FUN_0800aa3c(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_0800aa4c;
  if (param_1 != DAT_0800aa4c) {
    iVar1 = *(int *)(param_1 + 8) + 1;
  }
  if (param_1 != DAT_0800aa4c) {
    *(int *)(param_1 + 8) = iVar1;
  }
  return param_1 + 0xc;
}

