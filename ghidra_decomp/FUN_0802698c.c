
int FUN_0802698c(int *param_1)

{
  int *piVar1;
  int *piVar2;
  
  piVar1 = param_1;
  do {
    piVar2 = piVar1;
    piVar1 = piVar2 + 1;
  } while (*piVar2 != 0);
  return (int)piVar2 - (int)param_1 >> 2;
}

