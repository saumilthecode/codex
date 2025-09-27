
void FUN_0800890c(undefined4 *param_1,undefined4 *param_2)

{
  int *piVar1;
  int *piVar2;
  
  piVar2 = (int *)*param_2;
  piVar1 = (int *)*DAT_08008920;
  *param_1 = piVar2;
  if (piVar2 != piVar1) {
    *piVar2 = *piVar2 + 1;
  }
  return;
}

