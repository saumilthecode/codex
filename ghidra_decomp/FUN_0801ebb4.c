
int * FUN_0801ebb4(int *param_1,int param_2,int param_3,int param_4,undefined4 param_5)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  
  FUN_0801ea00(param_1,param_3,param_4,DAT_0801ec2c,param_1,param_2,param_3);
  uVar1 = FUN_0801eac4(param_1);
  uVar3 = (param_4 - param_3) + param_1[1];
  if (uVar1 < uVar3) {
    FUN_0801ead6(param_1,param_2,param_3,0,param_4);
  }
  else if ((param_1[1] != param_3 + param_2) && (param_3 != param_4)) {
    iVar2 = *param_1 + param_2 * 4;
    FUN_0801ea46(iVar2 + param_4 * 4,iVar2 + param_3 * 4);
  }
  if (param_4 != 0) {
    FUN_0801ea5e(*param_1 + param_2 * 4,param_4,param_5);
  }
  FUN_0801e978(param_1,uVar3);
  return param_1;
}

