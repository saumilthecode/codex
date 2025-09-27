
undefined4 * FUN_0800a2f0(undefined4 *param_1,int *param_2)

{
  undefined4 uVar1;
  int *extraout_r1;
  int *piStack_c;
  
  piStack_c = param_2;
  if (param_2[6] == 0) {
    FUN_080104fc(DAT_0800a314);
    param_2 = extraout_r1;
  }
  uVar1 = FUN_080090e8(*param_2,param_2[1] + *param_2,&piStack_c);
  *param_1 = uVar1;
  return param_1;
}

