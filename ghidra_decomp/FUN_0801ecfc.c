
int * FUN_0801ecfc(int *param_1,int param_2,int param_3,undefined4 param_4,int param_5)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  FUN_0801ea00(param_1,param_3,param_5,DAT_0801ed90,param_1,param_2,param_3);
  uVar1 = FUN_0801eac4(param_1);
  uVar5 = (param_5 - param_3) + param_1[1];
  if (uVar1 < uVar5) {
    FUN_0801ead6(param_1,param_2,param_3,param_4,param_5);
  }
  else {
    iVar4 = *param_1 + param_2 * 4;
    iVar3 = param_1[1] - (param_2 + param_3);
    iVar2 = FUN_0801ea18(param_1,param_4);
    if (iVar2 == 0) {
      FUN_0801ec66(param_1,iVar4,param_3,param_4,param_5,iVar3);
    }
    else {
      if ((iVar3 != 0) && (param_3 != param_5)) {
        FUN_0801ea46(iVar4 + param_5 * 4,iVar4 + param_3 * 4,iVar3);
      }
      if (param_5 != 0) {
        FUN_0801ea32(iVar4,param_4,param_5);
      }
    }
  }
  FUN_0801e978(param_1,uVar5);
  return param_1;
}

