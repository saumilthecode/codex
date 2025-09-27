
undefined4 * FUN_0801e678(undefined4 *param_1,undefined4 param_2,int param_3,int param_4)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  undefined8 uVar9;
  undefined4 uStack_2c;
  int iStack_28;
  
  uVar1 = DAT_0801e730;
  *param_1 = DAT_0801e730;
  uStack_2c = param_2;
  iStack_28 = param_3;
  iVar2 = FUN_0801e62c(param_3,param_4,&uStack_2c,uVar1,param_1);
  uVar6 = DAT_0801e734;
  iVar3 = FUN_080187c6();
  uVar8 = param_4 - param_3 >> 1;
  if (uVar6 < (uint)(param_4 - param_3)) {
    iVar4 = -1;
  }
  else {
    iVar4 = uVar8 << 2;
  }
  iVar5 = thunk_FUN_08008466(iVar4);
  iVar4 = iVar2;
  while( true ) {
    uVar9 = FUN_0801fa18(param_2,iVar5,iVar4,uVar8);
    uVar6 = (uint)uVar9;
    if (uVar8 <= uVar6) {
      uVar8 = uVar6 + 1;
      if (iVar5 != 0) {
        thunk_FUN_080249c4(iVar5,(int)((ulonglong)uVar9 >> 0x20),uVar6);
      }
      if (uVar8 < 0x1fffffff) {
        iVar5 = uVar8 * 4;
      }
      else {
        iVar5 = -1;
      }
      iVar5 = thunk_FUN_08008466(iVar5);
      uVar6 = FUN_0801fa18(param_2,iVar5,iVar4,uVar8);
    }
    FUN_0800b140(param_1,iVar5,uVar6);
    iVar7 = FUN_0802698c(iVar4);
    iVar4 = iVar4 + iVar7 * 4;
    if (iVar2 + iVar3 * 4 == iVar4) break;
    iVar4 = iVar4 + 4;
    FUN_0800b26e(param_1,0);
  }
  if (iVar5 != 0) {
    thunk_FUN_080249c4(iVar5);
  }
  FUN_08018900(iVar2);
  return param_1;
}

