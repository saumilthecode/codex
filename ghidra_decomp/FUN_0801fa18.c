
int FUN_0801fa18(undefined4 param_1,int *param_2,int *param_3,int param_4)

{
  int iVar1;
  int *piVar2;
  int *piVar3;
  
  piVar3 = param_3;
  if (param_4 == 0) {
LAB_0802ad9e:
    do {
      piVar2 = piVar3 + 1;
      iVar1 = *piVar3;
      piVar3 = piVar2;
    } while (iVar1 != 0);
  }
  else {
    do {
      param_4 = param_4 + -1;
      if (param_4 == 0) {
        *param_2 = 0;
        goto LAB_0802ad9e;
      }
      piVar2 = piVar3 + 1;
      iVar1 = *piVar3;
      *param_2 = iVar1;
      param_2 = param_2 + 1;
      piVar3 = piVar2;
    } while (iVar1 != 0);
  }
  return ((int)piVar2 - (int)param_3 >> 2) + -1;
}

