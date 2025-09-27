
int FUN_0800909c(int param_1,int param_2)

{
  int iVar1;
  int iVar2;
  
  iVar1 = DAT_080090e4;
  if (param_1 != param_2) {
    if (param_1 == 0) {
      FUN_080104fc(DAT_080090e0);
      iVar1 = DAT_080090e4;
    }
    else {
      iVar2 = param_2 - param_1 >> 2;
      iVar1 = FUN_0800add0(iVar2,0);
      FUN_0800acc8(iVar1 + 0xc,param_1,param_2);
      FUN_0800adb8(iVar1,iVar2);
      iVar1 = iVar1 + 0xc;
    }
  }
  return iVar1;
}

