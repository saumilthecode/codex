
int thunk_FUN_0802ad68(int param_1,int *param_2)

{
  int iVar1;
  int *piVar2;
  
  piVar2 = (int *)(param_1 + -4);
  do {
    piVar2 = piVar2 + 1;
    iVar1 = *piVar2;
    if (iVar1 != *param_2) {
      return iVar1 - *param_2;
    }
    param_2 = param_2 + 1;
  } while (iVar1 != 0);
  return 0;
}

