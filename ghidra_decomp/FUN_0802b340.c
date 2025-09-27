
int FUN_0802b340(undefined4 param_1,int param_2)

{
  int iVar1;
  
  iVar1 = FUN_0800670c(param_1,param_2,0,0);
  if (iVar1 == 0) {
    iVar1 = FUN_0802b370(param_1,param_2);
    return iVar1;
  }
  iVar1 = FUN_0802b370(param_1,param_2 + -0x80000000);
  return -iVar1;
}

