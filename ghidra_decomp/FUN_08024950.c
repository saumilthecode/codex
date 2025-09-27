
int * FUN_08024950(int *param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  undefined4 uVar2;
  
  *param_1 = (int)(param_1 + 2);
  if (param_3 == 1) {
    uVar1 = 0xe;
  }
  else {
    uVar1 = 0xd;
  }
  param_1[1] = 0;
  *(undefined1 *)(param_1 + 2) = 0;
  uVar2 = DAT_08024984;
  if (param_3 != 1) {
    uVar2 = DAT_08024988;
  }
  FUN_08018064(param_1,0,0,uVar2,uVar1,param_2);
  return param_1;
}

