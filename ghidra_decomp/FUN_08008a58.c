
void FUN_08008a58(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  undefined8 uVar10;
  
  if (param_3 != 0) {
    uVar1 = FUN_08008a40(param_2);
    if (*(int *)(param_1 + 8) - 1U < uVar1) {
      uVar8 = uVar1 + 4;
      if (uVar8 < 0x1fffffff) {
        iVar9 = uVar8 * 4;
      }
      else {
        iVar9 = -1;
      }
      iVar7 = *(int *)(param_1 + 4);
      iVar2 = thunk_FUN_08008466(iVar9);
      uVar4 = *(uint *)(param_1 + 8);
      for (uVar3 = 0; uVar3 != uVar4; uVar3 = uVar3 + 1) {
        *(undefined4 *)(iVar2 + uVar3 * 4) = *(undefined4 *)(*(int *)(param_1 + 4) + uVar3 * 4);
      }
      for (; uVar4 < uVar8; uVar4 = uVar4 + 1) {
        *(undefined4 *)(iVar2 + uVar4 * 4) = 0;
      }
      iVar5 = *(int *)(param_1 + 0xc);
      iVar9 = thunk_FUN_08008466(iVar9);
      uVar4 = *(uint *)(param_1 + 8);
      for (uVar3 = 0; uVar3 != uVar4; uVar3 = uVar3 + 1) {
        *(undefined4 *)(iVar9 + uVar3 * 4) = *(undefined4 *)(*(int *)(param_1 + 0xc) + uVar3 * 4);
      }
      for (; uVar4 < uVar8; uVar4 = uVar4 + 1) {
        *(undefined4 *)(iVar9 + uVar4 * 4) = 0;
      }
      *(int *)(param_1 + 4) = iVar2;
      *(uint *)(param_1 + 8) = uVar8;
      *(int *)(param_1 + 0xc) = iVar9;
      if (iVar7 != 0) {
        thunk_FUN_080249c4(iVar7);
      }
      if (iVar5 != 0) {
        thunk_FUN_080249c4(iVar5);
      }
    }
    iVar9 = *(int *)(param_1 + 4);
    *(int *)(param_3 + 4) = *(int *)(param_3 + 4) + 1;
    piVar6 = DAT_08008bac;
    if (*(int *)(iVar9 + uVar1 * 4) != 0) {
      for (; *piVar6 != 0; piVar6 = piVar6 + 2) {
        uVar8 = FUN_08008a40(*piVar6);
        iVar2 = piVar6[1];
        if (uVar1 == uVar8) {
          iVar7 = FUN_08008a40(iVar2);
          if (*(int *)(iVar9 + iVar7 * 4) != 0) {
            iVar2 = FUN_0800c968(param_3,iVar2);
LAB_08008b72:
            *(int *)(iVar2 + 4) = *(int *)(iVar2 + 4) + 1;
            FUN_080088fa(*(undefined4 *)(iVar9 + iVar7 * 4));
            *(int *)(iVar9 + iVar7 * 4) = iVar2;
          }
          break;
        }
        uVar10 = FUN_08008a40(iVar2);
        if (uVar1 == (uint)uVar10) {
          iVar7 = FUN_08008a40((int)((ulonglong)uVar10 >> 0x20));
          if (*(int *)(iVar9 + iVar7 * 4) != 0) {
            iVar2 = FUN_08009e78(param_3);
            goto LAB_08008b72;
          }
          break;
        }
      }
      FUN_080088fa(*(undefined4 *)(iVar9 + uVar1 * 4));
    }
    *(int *)(iVar9 + uVar1 * 4) = param_3;
    for (uVar1 = 0; uVar1 < *(uint *)(param_1 + 8); uVar1 = uVar1 + 1) {
      if (*(int *)(*(int *)(param_1 + 0xc) + uVar1 * 4) != 0) {
        FUN_080088fa();
        *(undefined4 *)(*(int *)(param_1 + 0xc) + uVar1 * 4) = 0;
      }
    }
  }
  return;
}

