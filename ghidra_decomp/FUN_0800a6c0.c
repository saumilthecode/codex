
uint FUN_0800a6c0(int *param_1,undefined4 param_2,uint param_3,int param_4)

{
  int iVar1;
  uint uVar2;
  
  FUN_0800a650(param_1,param_4,DAT_0800a6f8);
  iVar1 = FUN_0800a648(param_1);
  uVar2 = iVar1 - param_4;
  if (param_3 <= (uint)(iVar1 - param_4)) {
    uVar2 = param_3;
  }
  if (uVar2 != 0) {
    FUN_0800a5f0(param_2,*param_1 + param_4,uVar2);
  }
  return uVar2;
}

