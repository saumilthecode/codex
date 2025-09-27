
void FUN_08021b38(int *param_1,int param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int extraout_r1;
  
  *param_1 = (int)(param_1 + 2);
  iVar1 = param_2;
  if (param_2 == 0) {
    FUN_080104fc(DAT_08021b60);
    iVar1 = extraout_r1;
  }
  iVar1 = FUN_08005ea0(iVar1);
  FUN_08021aee(param_1,param_2,param_2 + iVar1,param_4);
  return;
}

