
void FUN_0801886c(int *param_1,int param_2,undefined4 param_3)

{
  int iVar1;
  int iVar2;
  
  if (param_2 == 0) {
    FUN_080104fc(DAT_080188bc);
    iVar2 = DAT_080188c0;
  }
  else {
    iVar1 = FUN_08005ea0(param_2);
    iVar2 = DAT_080188c0;
    if (param_2 != param_2 + iVar1) {
      iVar2 = FUN_0800a764(iVar1,0,param_3);
      FUN_0800a63e(iVar2 + 0xc,param_2,param_2 + iVar1);
      FUN_0800a74c(iVar2,iVar1);
      iVar2 = iVar2 + 0xc;
    }
  }
  *param_1 = iVar2;
  return;
}

