
int FUN_0801e7fe(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                undefined4 param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  
  uStack_2c = param_2;
  uStack_28 = param_3;
  iVar1 = FUN_0801e62c(param_2,param_3,&uStack_2c,param_4,param_1);
  iVar2 = FUN_0801e62c(param_4,param_5,&uStack_2c);
  iVar3 = FUN_080187c6(iVar1);
  iVar4 = FUN_080187c6(iVar2);
  iVar6 = iVar2 + iVar4 * 4;
  iVar4 = iVar2;
  iVar7 = iVar1;
  do {
    iVar5 = FUN_0801fa02(param_1,iVar7,iVar4);
    if (iVar5 != 0) {
LAB_0801e864:
      FUN_08018900(iVar2);
      FUN_08018900(iVar1);
      return iVar5;
    }
    iVar5 = FUN_0802698c(iVar7);
    iVar7 = iVar7 + iVar5 * 4;
    iVar5 = FUN_0802698c(iVar4);
    iVar4 = iVar4 + iVar5 * 4;
    if (iVar1 + iVar3 * 4 == iVar7) {
      iVar5 = iVar6 - iVar4;
      if (iVar5 != 0) {
        iVar5 = -1;
      }
      goto LAB_0801e864;
    }
    if (iVar6 == iVar4) {
      iVar5 = 1;
      goto LAB_0801e864;
    }
    iVar7 = iVar7 + 4;
    iVar4 = iVar4 + 4;
  } while( true );
}

