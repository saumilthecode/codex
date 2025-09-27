
int * FUN_08008a10(int *param_1,int *param_2)

{
  int *piVar1;
  int *piVar2;
  int *piVar3;
  int *piVar4;
  
  piVar4 = (int *)*param_2;
  piVar2 = (int *)*DAT_08008a3c;
  piVar3 = DAT_08008a3c;
  if (piVar4 != piVar2) {
    piVar3 = (int *)*piVar4;
  }
  piVar1 = (int *)*param_1;
  if (piVar4 != piVar2) {
    *piVar4 = (int)piVar3 + 1;
  }
  if (piVar2 != piVar1) {
    FUN_080089d6();
  }
  *param_1 = *param_2;
  return param_1;
}

