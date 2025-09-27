
void FUN_0801ea7c(undefined4 *param_1,uint param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 uVar1;
  uint local_14;
  undefined4 uStack_10;
  
  local_14 = param_2;
  uStack_10 = param_3;
  if (3 < param_2) {
    uVar1 = FUN_0801e990(param_1,&local_14,0,param_4,param_1);
    *param_1 = uVar1;
    param_1[2] = local_14;
  }
  if (local_14 != 0) {
    FUN_0801ea5e(*param_1,local_14,param_3);
  }
  FUN_0801e978(param_1,local_14);
  return;
}

