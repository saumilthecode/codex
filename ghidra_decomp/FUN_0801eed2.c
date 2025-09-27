
void FUN_0801eed2(undefined4 param_1,int *param_2,undefined4 param_3,uint param_4)

{
  int iVar1;
  
  iVar1 = FUN_08008590();
  if ((iVar1 == 0) && (param_4 < 4)) {
                    /* WARNING: Could not recover jumptable at 0x0801eef6. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*param_2 + 0x14))(param_2,param_1,param_3);
    return;
  }
  return;
}

