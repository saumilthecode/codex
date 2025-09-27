
undefined4 * FUN_08011a70(undefined4 *param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  undefined8 uVar9;
  undefined4 uStack_24;
  
  uVar1 = DAT_08011b0c;
  *param_1 = DAT_08011b0c;
  uStack_24 = param_2;
  iVar2 = FUN_08011a24(param_3,param_4,&uStack_24,uVar1,param_1);
  iVar3 = FUN_08010c1a();
  uVar7 = (param_4 - param_3) * 2;
  iVar4 = thunk_FUN_08008466(uVar7);
  iVar8 = iVar2;
  while( true ) {
    uVar9 = FUN_0801f9f8(param_2,iVar4,iVar8,uVar7);
    uVar5 = (uint)uVar9;
    if (uVar7 <= uVar5) {
      uVar7 = uVar5 + 1;
      if (iVar4 != 0) {
        thunk_FUN_080249c4(iVar4,(int)((ulonglong)uVar9 >> 0x20),uVar5);
      }
      iVar4 = thunk_FUN_08008466(uVar7);
      uVar5 = FUN_0801f9f8(param_2,iVar4,iVar8,uVar7);
    }
    FUN_0800ab18(param_1,iVar4,uVar5);
    iVar6 = FUN_08005ea0(iVar8);
    if (iVar2 + iVar3 == iVar6 + iVar8) break;
    iVar8 = iVar6 + iVar8 + 1;
    FUN_0800ac3e(param_1,0);
  }
  if (iVar4 != 0) {
    thunk_FUN_080249c4(iVar4);
  }
  FUN_08010c74(iVar2);
  return param_1;
}

