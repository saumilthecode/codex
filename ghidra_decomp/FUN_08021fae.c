
undefined4 *
FUN_08021fae(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            int param_5,undefined1 param_6,undefined4 *param_7)

{
  bool bVar1;
  byte *pbVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined1 uVar6;
  undefined1 *puVar7;
  byte *pbVar8;
  uint uVar9;
  byte *pbVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  undefined1 *local_80;
  undefined4 local_6c;
  undefined4 local_64;
  undefined4 local_60;
  char local_5c;
  undefined3 uStack_5b;
  undefined1 *local_58;
  int local_54;
  undefined1 local_50 [16];
  undefined1 *local_40;
  uint local_3c;
  undefined1 local_38 [20];
  
  iVar3 = FUN_0801126c(param_5 + 0x6c);
  iVar4 = FUN_08021da0(param_5 + 0x6c);
  pbVar10 = (byte *)*param_7;
  if (*pbVar10 == *(byte *)(iVar4 + 0x38)) {
    local_64 = *(undefined4 *)(iVar4 + 0x34);
    local_80 = *(undefined1 **)(iVar4 + 0x24);
    uVar13 = *(uint *)(iVar4 + 0x28);
    if (param_7[1] != 0) {
      pbVar10 = pbVar10 + 1;
    }
  }
  else {
    local_64 = *(undefined4 *)(iVar4 + 0x30);
    uVar13 = *(uint *)(iVar4 + 0x20);
    local_80 = *(undefined1 **)(iVar4 + 0x1c);
  }
  pbVar2 = pbVar10;
  do {
    pbVar8 = pbVar2;
    if (pbVar10 + param_7[1] <= pbVar8) break;
    pbVar2 = pbVar8 + 1;
  } while ((int)((uint)*(byte *)(*(int *)(iVar3 + 0x18) + (uint)*pbVar8) << 0x1d) < 0);
  iVar3 = (int)pbVar8 - (int)pbVar10;
  local_6c = param_4;
  if (iVar3 != 0) {
    local_58 = local_50;
    local_54 = 0;
    local_50[0] = 0;
    FUN_08017ea8(&local_58,iVar3 * 2);
    iVar11 = iVar3 - *(int *)(iVar4 + 0x2c);
    if (0 < iVar11) {
      if (*(int *)(iVar4 + 0x2c) < 0) {
        iVar11 = iVar3;
      }
      if (*(int *)(iVar4 + 0xc) == 0) {
        FUN_08018064(&local_58,0,local_54,pbVar10,iVar11);
      }
      else {
        FUN_08017f10(&local_58,0,local_54,iVar11 << 1,0);
        iVar5 = FUN_0801147a(local_58,*(undefined1 *)(iVar4 + 0x12),*(undefined4 *)(iVar4 + 8),
                             *(undefined4 *)(iVar4 + 0xc),pbVar10,pbVar10 + iVar11);
        FUN_08021d60(&local_58,iVar5 - (int)local_58,0xffffffff);
      }
    }
    if (0 < *(int *)(iVar4 + 0x2c)) {
      FUN_08017ede(&local_58,*(undefined1 *)(iVar4 + 0x11));
      if (iVar11 < 0) {
        FUN_08021c14(&local_58,-iVar11,*(undefined1 *)(iVar4 + 0x39));
      }
      else {
        iVar3 = *(int *)(iVar4 + 0x2c);
        pbVar10 = pbVar10 + iVar11;
      }
      FUN_08021c28(&local_58,pbVar10,iVar3);
    }
    uVar14 = *(uint *)(param_5 + 0xc) & 0xb0;
    uVar9 = *(uint *)(param_5 + 0xc) & 0x200;
    if (uVar9 != 0) {
      uVar9 = *(uint *)(iVar4 + 0x18);
    }
    uVar9 = uVar9 + local_54 + uVar13;
    iVar3 = 0;
    local_40 = local_38;
    local_3c = 0;
    local_38[0] = 0;
    FUN_08017ea8(&local_40,uVar9 * 2);
    uVar12 = *(uint *)(param_5 + 8);
    bVar1 = uVar14 == 0x10 && uVar9 < uVar12;
    do {
      switch(*(undefined1 *)((int)&local_64 + iVar3)) {
      case 0:
        if (bVar1) {
LAB_080221d0:
          FUN_08021c14(&local_40,uVar12 - uVar9,param_6);
        }
        break;
      case 1:
        uVar6 = param_6;
        if (bVar1) goto LAB_080221d0;
LAB_080221be:
        FUN_08017ede(&local_40,uVar6);
        break;
      case 2:
        if (*(int *)(param_5 + 0xc) << 0x16 < 0) {
          puVar7 = *(undefined1 **)(iVar4 + 0x14);
          iVar11 = *(int *)(iVar4 + 0x18);
          goto LAB_0802212e;
        }
        break;
      case 3:
        if (uVar13 != 0) {
          uVar6 = *local_80;
          goto LAB_080221be;
        }
        break;
      case 4:
        puVar7 = local_58;
        iVar11 = local_54;
LAB_0802212e:
        FUN_08021c28(&local_40,puVar7,iVar11);
      }
      iVar3 = iVar3 + 1;
    } while (iVar3 != 4);
    if (1 < uVar13) {
      FUN_08021c28(&local_40,local_80 + 1,uVar13 - 1);
    }
    uVar13 = local_3c;
    if (local_3c < uVar12) {
      uVar13 = uVar12;
      if (uVar14 == 0x20) {
        FUN_08021c14(&local_40,uVar12 - local_3c,param_6);
      }
      else {
        FUN_08017f10(&local_40,0,0,uVar12 - local_3c,param_6);
      }
    }
    local_6c._0_1_ = (char)param_4;
    if (((char)local_6c == '\0') && (uVar9 = FUN_08017c9a(param_3,local_40,uVar13), uVar13 != uVar9)
       ) {
      local_6c._0_1_ = '\x01';
    }
    _local_5c = CONCAT31(uStack_5b,(char)local_6c);
    local_6c._1_3_ = (undefined3)((uint)param_4 >> 8);
    local_60 = param_3;
    FUN_08006cec(&local_40);
    FUN_08006cec(&local_58);
  }
  *(undefined4 *)(param_5 + 8) = 0;
  *param_1 = param_3;
  param_1[1] = local_6c;
  return param_1;
}

