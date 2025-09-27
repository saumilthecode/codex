
int * FUN_08018064(int *param_1,int param_2,int param_3,undefined4 param_4,int param_5)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  
  FUN_08017d3c(param_1,param_3,param_5,DAT_080180fc,param_1,param_2,param_3);
  uVar1 = FUN_08017e26(param_1);
  uVar5 = (param_5 - param_3) + param_1[1];
  if (uVar1 < uVar5) {
    FUN_08017e38(param_1,param_2,param_3,param_4,param_5);
  }
  else {
    iVar4 = *param_1 + param_2;
    iVar3 = param_1[1] - (param_2 + param_3);
    iVar2 = FUN_08017d54(param_1,param_4);
    if (iVar2 == 0) {
      FUN_08017fe4(param_1,iVar4,param_3,param_4,param_5,iVar3);
    }
    else {
      if ((iVar3 != 0) && (param_3 != param_5)) {
        FUN_08017d80(iVar4 + param_5,iVar4 + param_3,iVar3);
      }
      if (param_5 != 0) {
        FUN_08017d6c(iVar4,param_4,param_5);
      }
    }
  }
  param_1[1] = uVar5;
  *(undefined1 *)(*param_1 + uVar5) = 0;
  return param_1;
}

