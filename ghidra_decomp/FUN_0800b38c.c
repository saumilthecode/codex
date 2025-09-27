
undefined4 * FUN_0800b38c(undefined4 *param_1,int param_2)

{
  undefined4 uVar1;
  
  uVar1 = DAT_0800b3b0;
  if (param_2 != 0) {
    param_2 = 1;
  }
  param_1[1] = param_2;
  *param_1 = uVar1;
  uVar1 = FUN_08008940();
  param_1[2] = uVar1;
  *(undefined1 *)(param_1 + 3) = 0;
  FUN_0800b6cc(param_1);
  return param_1;
}

