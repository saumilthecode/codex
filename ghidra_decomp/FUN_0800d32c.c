
void FUN_0800d32c(int *param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int extraout_r1;
  
  *param_1 = (int)(param_1 + 2);
  iVar1 = param_2;
  if (param_2 == 0) {
    FUN_080104fc(DAT_0800d358);
    iVar1 = extraout_r1;
  }
  iVar1 = FUN_0802698c(iVar1);
  FUN_0800d2de(param_1,param_2,param_2 + iVar1 * 4,param_4);
  return;
}

