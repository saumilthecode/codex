
void FUN_0800a7fc(int param_1)

{
  int iVar1;
  
  if (param_1 != DAT_0800a814) {
    iVar1 = *(int *)(param_1 + 8);
    *(int *)(param_1 + 8) = iVar1 + -1;
    if (iVar1 < 1) {
      thunk_FUN_080249c4();
    }
  }
  return;
}

