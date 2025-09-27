
void FUN_0800bc20(undefined4 *param_1,int param_2,int param_3)

{
  undefined4 uVar1;
  uint uVar2;
  int local_14;
  
  uVar2 = param_3 - param_2;
  local_14 = (int)uVar2 >> 2;
  if (0xc < uVar2) {
    uVar1 = FUN_0801e990(param_1,&local_14,0,uVar2,param_1);
    *param_1 = uVar1;
    param_1[2] = local_14;
  }
  FUN_0801eab8(*param_1,param_2,param_3);
  FUN_0801e978(param_1,local_14);
  return;
}

