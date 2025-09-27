
undefined4 FUN_0800a918(undefined4 param_1,int param_2,uint param_3,undefined4 param_4)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  
  uVar1 = FUN_0800a650(param_1,param_2,DAT_0800a948,param_4,param_4);
  iVar2 = FUN_0800a648(param_1);
  uVar3 = iVar2 - param_2;
  if (param_3 <= (uint)(iVar2 - param_2)) {
    uVar3 = param_3;
  }
  FUN_0800a844(param_1,uVar1,uVar3,0);
  return param_1;
}

