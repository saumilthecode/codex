
undefined4 FUN_0801f1a6(int *param_1,int param_2,int param_3,undefined4 param_4,int param_5)

{
  undefined4 uVar1;
  
  if (param_2 < 0) {
    if (param_2 != -2) {
                    /* WARNING: Could not recover jumptable at 0x0801f1cc. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (**(code **)(*param_1 + 0x20))();
      return uVar1;
    }
    uVar1 = 1;
  }
  else if (param_5 == param_3 + param_2) {
    uVar1 = 6;
  }
  else {
    uVar1 = 1;
  }
  return uVar1;
}

