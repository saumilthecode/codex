
int FUN_0800b060(int param_1)

{
  int iVar1;
  
  iVar1 = DAT_0800b070;
  if (param_1 != DAT_0800b070) {
    iVar1 = *(int *)(param_1 + 8) + 1;
  }
  if (param_1 != DAT_0800b070) {
    *(int *)(param_1 + 8) = iVar1;
  }
  return param_1 + 0xc;
}

