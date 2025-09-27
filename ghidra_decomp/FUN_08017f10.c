
int * FUN_08017f10(int *param_1,int param_2,int param_3,int param_4,undefined1 param_5)

{
  uint uVar1;
  uint uVar2;
  
  FUN_08017d3c(param_1,param_3,param_4,DAT_08017f88,param_1,param_2,param_3);
  uVar1 = FUN_08017e26(param_1);
  uVar2 = (param_4 - param_3) + param_1[1];
  if (uVar1 < uVar2) {
    FUN_08017e38(param_1,param_2,param_3,0,param_4);
  }
  else if ((param_1[1] != param_3 + param_2) && (param_3 != param_4)) {
    FUN_08017d80(*param_1 + param_2 + param_4,*param_1 + param_2 + param_3);
  }
  if (param_4 != 0) {
    FUN_08017d98(*param_1 + param_2,param_4,param_5);
  }
  param_1[1] = uVar2;
  *(undefined1 *)(*param_1 + uVar2) = 0;
  return param_1;
}

