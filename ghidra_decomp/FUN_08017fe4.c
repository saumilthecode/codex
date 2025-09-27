
void FUN_08017fe4(undefined4 param_1,int param_2,uint param_3,uint param_4,uint param_5,int param_6)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  if (param_5 == 0) {
LAB_08018002:
    if (param_6 == 0) {
      return;
    }
    if (param_5 == param_3) {
      return;
    }
  }
  else {
    if (param_5 <= param_3) {
      FUN_08017d80(param_2,param_4,param_5);
      goto LAB_08018002;
    }
    if (param_6 == 0) goto LAB_0801801a;
  }
  FUN_08017d80(param_2 + param_5,param_2 + param_3,param_6);
  if (param_5 <= param_3) {
    return;
  }
LAB_0801801a:
  uVar1 = param_2 + param_3;
  if (uVar1 < param_4 + param_5) {
    if (param_4 < uVar1) {
      iVar3 = uVar1 - param_4;
      FUN_08017d80(param_2,param_4,iVar3);
      uVar1 = param_5 - iVar3;
      iVar2 = param_2 + param_5;
      param_2 = param_2 + iVar3;
    }
    else {
      iVar2 = (param_4 - param_3) + param_5;
      uVar1 = param_5;
    }
    FUN_08017d6c(param_2,iVar2,uVar1);
  }
  else {
    FUN_08017d80(param_2,param_4,param_5);
  }
  return;
}

