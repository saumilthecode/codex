
void FUN_0800b224(undefined4 param_1,uint param_2,undefined4 param_3,undefined4 param_4)

{
  uint uVar1;
  
  uVar1 = FUN_0800acd4();
  FUN_0800ad00(param_1,uVar1,param_2,DAT_0800b260,param_4);
  if (uVar1 < param_2) {
    FUN_0800b1c0(param_1,param_2 - uVar1,param_3);
  }
  else if (param_2 < uVar1) {
    FUN_0800af58(param_1,param_2,0xffffffff);
  }
  return;
}

