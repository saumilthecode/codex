
uint FUN_0801eddc(int *param_1,undefined4 param_2,uint param_3,int param_4)

{
  uint uVar1;
  
  FUN_0801e9e4(param_1,param_4,DAT_0801ee10);
  uVar1 = param_1[1] - param_4;
  if (param_3 <= (uint)(param_1[1] - param_4)) {
    uVar1 = param_3;
  }
  if (uVar1 != 0) {
    FUN_0801ea32(param_2,*param_1 + param_4 * 4,uVar1);
  }
  return uVar1;
}

