
int FUN_08011c10(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                undefined4 param_5)

{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  undefined4 uStack_2c;
  undefined4 uStack_28;
  
  uStack_2c = param_2;
  uStack_28 = param_3;
  iVar1 = FUN_08011a24(param_2,param_3,&uStack_2c,param_4,param_1);
  iVar2 = FUN_08011a24(param_4,param_5,&uStack_2c);
  iVar3 = FUN_08010c1a(iVar1);
  iVar4 = FUN_08010c1a(iVar2);
  iVar7 = iVar2;
  iVar8 = iVar1;
  do {
    iVar5 = FUN_0801f9e2(param_1,iVar8,iVar7);
    if (iVar5 != 0) {
LAB_08011c72:
      FUN_08010c74(iVar2);
      FUN_08010c74(iVar1);
      return iVar5;
    }
    iVar5 = FUN_08005ea0(iVar8);
    iVar6 = FUN_08005ea0(iVar7);
    iVar7 = iVar7 + iVar6;
    if (iVar1 + iVar3 == iVar8 + iVar5) {
      iVar5 = (iVar2 + iVar4) - iVar7;
      if (iVar5 != 0) {
        iVar5 = -1;
      }
      goto LAB_08011c72;
    }
    if (iVar2 + iVar4 == iVar7) {
      iVar5 = 1;
      goto LAB_08011c72;
    }
    iVar8 = iVar8 + iVar5 + 1;
    iVar7 = iVar7 + 1;
  } while( true );
}

