
int FUN_080090e8(int param_1,int param_2)

{
  int iVar1;
  
  iVar1 = DAT_08009130;
  if (param_1 != param_2) {
    if (param_1 == 0) {
      FUN_080104fc(DAT_0800912c);
      iVar1 = DAT_08009130;
    }
    else {
      iVar1 = FUN_0800a764(param_2 - param_1,0);
      FUN_0800a63e(iVar1 + 0xc,param_1,param_2);
      FUN_0800a74c(iVar1,param_2 - param_1);
      iVar1 = iVar1 + 0xc;
    }
  }
  return iVar1;
}

