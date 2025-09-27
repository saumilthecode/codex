
int FUN_0800a7c4(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  
  iVar1 = DAT_0800a7f4;
  if (param_1 != 0) {
    iVar1 = FUN_0800a764(param_1,0,param_3,param_4,param_4);
    FUN_0800a620(iVar1 + 0xc,param_1,param_2);
    FUN_0800a74c(iVar1,param_1);
    iVar1 = iVar1 + 0xc;
  }
  return iVar1;
}

