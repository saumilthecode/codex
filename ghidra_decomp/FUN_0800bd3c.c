
void FUN_0800bd3c(int *param_1,int *param_2,undefined4 param_3,undefined4 param_4)

{
  if ((code *)param_1[6] != (code *)0x0) {
    (*(code *)param_1[6])();
  }
  *param_1 = (int)(param_1 + 2);
  FUN_0800bc9c(param_1,*param_2,param_2[1] + *param_2,param_1 + 2,param_4);
  param_1[6] = DAT_0800bd60;
  return;
}

