
void FUN_0802ad80(int *param_1,int param_2)

{
  int *piVar1;
  
  *param_1 = 0;
  piVar1 = (int *)(param_2 + -4);
  while( true ) {
    piVar1 = piVar1 + 1;
    if (*piVar1 == 0) break;
    *param_1 = *piVar1;
    param_1 = param_1 + 1;
  }
  *param_1 = 0;
  return;
}

