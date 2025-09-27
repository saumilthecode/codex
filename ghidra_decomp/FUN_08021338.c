
undefined4 FUN_08021338(int *param_1,int *param_2,uint param_3,undefined4 param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  FUN_08021240(param_1,param_4,param_3,param_4,param_4);
  while( true ) {
    iVar3 = *param_1;
    iVar4 = param_1[1];
    if ((iVar3 == iVar4) || (param_2[1] == *param_2)) {
      if (iVar3 != iVar4) {
        return 1;
      }
      return 0;
    }
    uVar1 = FUN_08020d42(param_1,param_3);
    if (uVar1 == 0xfffffffe) {
      return 1;
    }
    if (param_3 < uVar1) break;
    iVar2 = FUN_08020fc4(param_2,uVar1,param_4);
    if (iVar2 == 0) {
      *param_1 = iVar3;
      param_1[1] = iVar4;
      return 1;
    }
  }
  return 2;
}

