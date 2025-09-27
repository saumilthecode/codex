
void FUN_0801ec66(undefined4 param_1,int param_2,uint param_3,uint param_4,uint param_5,int param_6)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  
  uVar4 = param_4;
  if (param_5 == 0) {
LAB_0801ec84:
    if (param_6 == 0) {
      return;
    }
    if (param_5 == param_3) {
      return;
    }
  }
  else {
    if (param_5 <= param_3) {
      FUN_0801ea46(param_2,param_4,param_5,param_4,param_4);
      goto LAB_0801ec84;
    }
    if (param_6 == 0) goto LAB_0801eca0;
  }
  FUN_0801ea46(param_2 + param_5 * 4,param_2 + param_3 * 4,param_6);
  if (param_5 <= param_3) {
    return;
  }
LAB_0801eca0:
  uVar2 = param_2 + param_3 * 4;
  iVar3 = param_5 << 2;
  if (uVar2 < param_4 + param_5 * 4) {
    if (param_4 < uVar2) {
      iVar1 = (int)(uVar2 - param_4) >> 2;
      FUN_0801ea46(param_2,param_4,iVar1,uVar2,uVar4);
      param_5 = param_5 - iVar1;
      iVar1 = param_2 + (uVar2 - param_4);
    }
    else {
      iVar3 = ((param_5 + ((int)(param_4 - param_2) >> 2)) - param_3) * 4;
      iVar1 = param_2;
    }
    FUN_0801ea32(iVar1,param_2 + iVar3,param_5);
  }
  else {
    FUN_0801ea46(param_2,param_4,param_5,uVar2,uVar4);
  }
  return;
}

