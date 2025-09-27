
void FUN_08010bc6(int *param_1)

{
  if ((uint)param_1[2] < (uint)param_1[3]) {
    param_1[2] = param_1[2] + 1;
    return;
  }
                    /* WARNING: Could not recover jumptable at 0x08010bd8. Too many branches */
                    /* WARNING: Treating indirect jump as call */
  (**(code **)(*param_1 + 0x28))();
  return;
}

