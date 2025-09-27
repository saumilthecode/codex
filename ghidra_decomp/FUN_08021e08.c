
void FUN_08021e08(int *param_1,int param_2,int param_3,undefined4 param_4)

{
  if ((char)param_1[7] != '\x01') {
    if ((char)param_1[7] == '\0') {
      FUN_0800b34a();
    }
                    /* WARNING: Could not recover jumptable at 0x08021e44. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*param_1 + 0x1c))(param_1,param_2,param_3,param_4);
    return;
  }
  if (param_2 != param_3) {
    FUN_08028666(param_4,param_2,param_3 - param_2);
    return;
  }
  return;
}

