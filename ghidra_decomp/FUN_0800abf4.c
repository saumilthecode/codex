
void FUN_0800abf4(undefined4 param_1,uint param_2,undefined4 param_3,undefined4 param_4)

{
  uint uVar1;
  
  uVar1 = FUN_0800a648();
  FUN_0800a674(param_1,uVar1,param_2,DAT_0800ac30,param_4);
  if (uVar1 < param_2) {
    FUN_0800ab94(param_1,param_2 - uVar1,param_3);
  }
  else if (param_2 < uVar1) {
    FUN_0800a918(param_1,param_2,0xffffffff);
  }
  return;
}

