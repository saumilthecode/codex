
undefined4 *
FUN_0801175c(undefined4 *param_1,undefined4 *param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_08010c1a(*param_2);
  *param_1 = (int)uVar2;
  uVar1 = thunk_FUN_08008466();
  param_1[1] = uVar1;
  FUN_0800a6c0((int)((ulonglong)uVar2 >> 0x20),uVar1,*param_1,0,param_4);
  return param_1;
}

