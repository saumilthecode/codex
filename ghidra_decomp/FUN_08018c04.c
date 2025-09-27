
undefined4 * FUN_08018c04(undefined4 *param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  
  uVar1 = DAT_08018c28;
  if (param_3 != 0) {
    param_3 = 1;
  }
  param_1[1] = param_3;
  *param_1 = uVar1;
  param_1[2] = param_2;
  uVar1 = FUN_08008954();
  param_1[4] = uVar1;
  FUN_08020a90(param_1,0);
  return param_1;
}

