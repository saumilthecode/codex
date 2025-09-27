
undefined4 *
FUN_08012a7c(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            int param_5,undefined1 param_6,undefined4 *param_7)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  int iVar6;
  undefined1 uVar7;
  byte *pbVar8;
  byte *pbVar9;
  byte *pbVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  undefined1 *local_54;
  undefined4 local_48;
  undefined4 local_44;
  undefined4 local_3c;
  int local_38;
  int local_34;
  undefined4 local_30;
  undefined1 uStack_2c;
  
  iVar2 = FUN_0801126c(param_5 + 0x6c);
  iVar3 = FUN_08011878(param_5 + 0x6c);
  pbVar9 = (byte *)*param_7;
  if (*pbVar9 == *(byte *)(iVar3 + 0x38)) {
    local_3c = *(undefined4 *)(iVar3 + 0x34);
    uVar13 = *(uint *)(iVar3 + 0x28);
    local_54 = *(undefined1 **)(iVar3 + 0x24);
    iVar4 = FUN_08010c1a(pbVar9);
    pbVar8 = pbVar9;
    if (iVar4 != 0) {
      pbVar8 = pbVar9 + 1;
    }
  }
  else {
    local_3c = *(undefined4 *)(iVar3 + 0x30);
    uVar13 = *(uint *)(iVar3 + 0x20);
    local_54 = *(undefined1 **)(iVar3 + 0x1c);
    pbVar8 = pbVar9;
  }
  iVar4 = FUN_08010c1a(pbVar9);
  pbVar9 = pbVar8;
  do {
    pbVar10 = pbVar9;
    if (pbVar8 + iVar4 <= pbVar10) break;
    pbVar9 = pbVar10 + 1;
  } while ((int)((uint)*(byte *)(*(int *)(iVar2 + 0x18) + (uint)*pbVar10) << 0x1d) < 0);
  iVar2 = (int)pbVar10 - (int)pbVar8;
  local_48 = param_3;
  local_44 = param_4;
  if (iVar2 != 0) {
    local_38 = DAT_08012cdc;
    FUN_0800aa82(&local_38,iVar2 * 2);
    iVar4 = iVar2 - *(int *)(iVar3 + 0x2c);
    if (0 < iVar4) {
      if (*(int *)(iVar3 + 0x2c) < 0) {
        iVar4 = iVar2;
      }
      if (*(int *)(iVar3 + 0xc) == 0) {
        FUN_0800a9cc(&local_38,pbVar8,iVar4);
      }
      else {
        uVar5 = FUN_08010c1a(local_38);
        FUN_0800a94c(&local_38,0,uVar5,iVar4 << 1,0);
        FUN_0800a904(&local_38);
        iVar6 = FUN_0801147a(local_38,*(undefined1 *)(iVar3 + 0x12),*(undefined4 *)(iVar3 + 8),
                             *(undefined4 *)(iVar3 + 0xc),pbVar8,pbVar8 + iVar4);
        FUN_0800a904(&local_38);
        FUN_08010c40(&local_38,iVar6 - local_38,0xffffffff);
      }
    }
    if (0 < *(int *)(iVar3 + 0x2c)) {
      FUN_0800ac3e(&local_38,*(undefined1 *)(iVar3 + 0x11));
      if (iVar4 < 0) {
        FUN_0800ab94(&local_38,-iVar4,*(undefined1 *)(iVar3 + 0x39));
      }
      else {
        iVar2 = *(int *)(iVar3 + 0x2c);
        pbVar8 = pbVar8 + iVar4;
      }
      FUN_0800ab18(&local_38,pbVar8,iVar2);
    }
    uVar11 = *(uint *)(param_5 + 0xc);
    iVar2 = DAT_08012cdc;
    iVar4 = FUN_08010c1a(local_38);
    uVar14 = uVar11 & 0xb0;
    uVar11 = uVar11 & 0x200;
    if (uVar11 != 0) {
      uVar11 = *(uint *)(iVar3 + 0x18);
    }
    uVar11 = uVar11 + iVar4 + uVar13;
    local_34 = iVar2;
    FUN_0800aa82(&local_34,uVar11 * 2);
    uVar12 = *(uint *)(param_5 + 8);
    bVar1 = uVar14 == 0x10 && uVar11 < uVar12;
    iVar2 = 0;
    do {
      switch(*(undefined1 *)((int)&local_3c + iVar2)) {
      case 0:
        if (bVar1) {
LAB_08012ca8:
          FUN_0800ab94(&local_34,uVar12 - uVar11,param_6);
        }
        break;
      case 1:
        uVar7 = param_6;
        if (bVar1) goto LAB_08012ca8;
LAB_08012c92:
        FUN_0800ac3e(&local_34,uVar7);
        break;
      case 2:
        if (*(int *)(param_5 + 0xc) << 0x16 < 0) {
          FUN_0800ab18(&local_34,*(undefined4 *)(iVar3 + 0x14),*(undefined4 *)(iVar3 + 0x18));
        }
        break;
      case 3:
        if (uVar13 != 0) {
          uVar7 = *local_54;
          goto LAB_08012c92;
        }
        break;
      case 4:
        FUN_0800aac0(&local_34,&local_38);
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 != 4);
    if (1 < uVar13) {
      FUN_0800ab18(&local_34,local_54 + 1,uVar13 - 1);
    }
    iVar2 = local_34;
    uVar13 = FUN_08010c1a(local_34);
    if (uVar13 < uVar12) {
      if (uVar14 == 0x20) {
        FUN_0800ab94(&local_34,uVar12 - uVar13,param_6);
        uVar13 = uVar12;
      }
      else {
        uVar5 = FUN_08010c20(iVar2,0,DAT_08012ce0);
        FUN_0800a94c(&local_34,uVar5,0,uVar12 - uVar13,param_6);
        uVar13 = uVar12;
      }
    }
    FUN_08011c98(&local_30,param_3,param_4,local_34,uVar13);
    local_48 = local_30;
    local_44 = CONCAT31((int3)((uint)param_4 >> 8),uStack_2c);
    FUN_08010c74(local_34);
    FUN_08010c74(local_38);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *param_1 = local_48;
  param_1[1] = local_44;
  return param_1;
}

