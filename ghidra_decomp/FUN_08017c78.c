
undefined4 FUN_08017c78(int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  
  if ((undefined1 *)param_1[6] <= (undefined1 *)param_1[5]) {
                    /* WARNING: Could not recover jumptable at 0x08017c8a. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    uVar1 = (**(code **)(*param_1 + 0x34))();
    return uVar1;
  }
  *(undefined1 *)param_1[5] = (char)param_2;
  param_1[5] = param_1[5] + 1;
  return param_2;
}

