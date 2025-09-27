
void FUN_080088fa(int *param_1)

{
  int iVar1;
  
  iVar1 = param_1[1];
  param_1[1] = iVar1 + -1;
  if (iVar1 == 1) {
                    /* WARNING: Could not recover jumptable at 0x08008908. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (**(code **)(*param_1 + 4))();
    return;
  }
  return;
}

