
void FUN_080089d6(int *param_1)

{
  int iVar1;
  
  iVar1 = *param_1;
  *param_1 = iVar1 + -1;
  if (iVar1 == 1) {
    FUN_0800895c();
    thunk_FUN_080249c4(param_1);
    return;
  }
  return;
}

