
undefined4 *
FUN_08022888(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,uint *param_7,int param_8,uint param_9,
            int param_10,uint *param_11)

{
  bool bVar1;
  uint uVar2;
  undefined1 uVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  uint *puVar7;
  uint uVar9;
  uint uVar10;
  undefined4 uVar11;
  uint uVar12;
  uint uVar13;
  undefined4 uVar14;
  uint uVar15;
  uint *puVar16;
  undefined1 *puVar17;
  uint auStack_58 [5];
  int local_44;
  uint local_40;
  undefined4 *local_3c;
  uint local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  uint *puVar8;
  
  local_3c = param_1;
  local_30 = param_3;
  local_2c = param_4;
  local_34 = FUN_0801126c(param_10 + 0x6c);
  uVar10 = param_9;
  puVar6 = auStack_58 + param_9 * -2;
  local_40 = (uint)puVar6 >> 3;
  local_44 = param_9 << 2;
  puVar16 = puVar6 + param_9;
  iVar4 = FUN_08012ee0(&local_30,&param_5);
  if (iVar4 == 0) {
    uVar15 = 0;
    uVar11 = local_30;
    uVar14 = local_2c;
  }
  else {
    uVar3 = FUN_08012e9c(&local_30);
    uVar14 = local_2c;
    uVar11 = local_30;
    iVar4 = FUN_08010cdc(local_34,uVar3);
    local_38 = FUN_08010cd6(local_34,uVar3);
    uVar15 = 0;
    for (uVar12 = 0; uVar12 != param_9; uVar12 = uVar12 + 1) {
      iVar5 = FUN_08010cdc(local_34,**(undefined1 **)(param_8 + uVar12 * 4));
      if ((iVar5 == iVar4) ||
         (uVar13 = FUN_08010cd6(local_34,**(undefined1 **)(param_8 + uVar12 * 4)),
         uVar13 == local_38)) {
        auStack_58[4] = uVar15 << 2;
        uVar9 = FUN_08005ea0(*(undefined4 *)(param_8 + uVar12 * 4));
        uVar13 = auStack_58[4];
        puVar16[uVar15] = uVar9;
        *(uint *)((int)puVar6 + uVar13) = uVar12;
        uVar15 = uVar15 + 1;
      }
    }
  }
  uVar12 = 0;
  while (1 < uVar15) {
    uVar13 = *puVar16;
    puVar7 = puVar16 + 1;
    do {
      puVar8 = puVar7 + 1;
      if (*puVar7 <= uVar13) {
        uVar13 = *puVar7;
      }
      puVar7 = puVar8;
    } while (puVar8 != puVar16 + uVar15);
    uVar12 = uVar12 + 1;
    FUN_08021b24(uVar11);
    if (uVar12 == uVar13) {
      local_2c = 0xffffffff;
      local_30 = uVar11;
      local_38 = FUN_08012ee0(&local_30,&param_5);
      uVar11 = local_30;
      uVar14 = local_2c;
      if (local_38 != 0) {
        uVar3 = FUN_08012e9c(&local_30);
        auStack_58[4] = FUN_08010cdc(local_34,uVar3);
        uVar3 = FUN_08012e9c(&local_30);
        uVar14 = local_2c;
        uVar11 = local_30;
        auStack_58[3] = FUN_08010cd6(local_34,uVar3);
        uVar9 = 0;
        do {
          if (uVar13 < puVar16[uVar9]) {
            auStack_58[2] = *(int *)(param_8 + puVar6[uVar9] * 4);
            auStack_58[1] = uVar9;
            iVar4 = FUN_08010cdc(local_34,*(undefined1 *)(auStack_58[2] + uVar13));
            if ((iVar4 == auStack_58[4]) ||
               (iVar4 = FUN_08010cd6(local_34,*(undefined1 *)(auStack_58[2] + uVar13)),
               uVar9 = auStack_58[1], iVar4 == auStack_58[3])) goto LAB_0802298e;
          }
          uVar9 = uVar9 + 1;
        } while (uVar15 != uVar9);
        local_38 = 0;
      }
LAB_0802298e:
      uVar9 = 0;
      do {
        if ((puVar16[uVar9] == uVar13) == local_38) {
          uVar15 = uVar15 - 1;
          puVar6[uVar9] = puVar6[uVar15];
          puVar16[uVar9] = puVar16[uVar15];
        }
        else {
          uVar9 = uVar9 + 1;
        }
        uVar2 = local_40;
        iVar4 = local_44;
      } while (uVar9 < uVar15);
      if (local_38 != 0) {
        uVar13 = *puVar16;
        for (uVar9 = 1; uVar9 < uVar15; uVar9 = uVar9 + 1) {
          if (puVar16[uVar9] <= uVar13) {
            uVar13 = puVar16[uVar9];
          }
        }
        goto LAB_080229ce;
      }
      if (uVar15 == 2) {
        if ((int)(param_9 << 0x1f) < 0) goto LAB_08022ae0;
        uVar15 = *puVar6;
        if (uVar15 < param_9 >> 1) {
          if (uVar15 + (param_9 >> 1) == auStack_58[uVar10 * -2 + 1]) goto LAB_08022aac;
          goto LAB_08022ae0;
        }
        uVar15 = uVar15 - (param_9 >> 1);
        if (uVar15 != auStack_58[uVar10 * -2 + 1]) goto LAB_08022ae0;
        *puVar6 = uVar15;
        *(uint *)(iVar4 + uVar2 * 8) = puVar16[1];
      }
      else {
        bVar1 = true;
LAB_080229ee:
        if (uVar15 != 1) goto LAB_08022ae0;
        uVar13 = uVar12;
        if (!bVar1) goto LAB_080229f6;
      }
      goto LAB_08022aac;
    }
    uVar14 = 0xffffffff;
LAB_080229ce:
    if (uVar13 <= uVar12) {
      bVar1 = false;
      goto LAB_080229ee;
    }
    local_30 = uVar11;
    local_2c = uVar14;
    iVar4 = FUN_08012ee0(&local_30,&param_5);
    if (iVar4 == 0) {
      bVar1 = false;
      uVar11 = local_30;
      uVar14 = local_2c;
      goto LAB_080229ee;
    }
    uVar3 = FUN_08012e9c(&local_30);
    local_38 = FUN_08010cdc(local_34,uVar3);
    uVar3 = FUN_08012e9c(&local_30);
    uVar14 = local_2c;
    uVar11 = local_30;
    auStack_58[4] = FUN_08010cd6(local_34,uVar3);
    uVar13 = 0;
    while (uVar13 < uVar15) {
      auStack_58[3] = *(int *)(param_8 + puVar6[uVar13] * 4);
      uVar9 = FUN_08010cdc(local_34,*(undefined1 *)(auStack_58[3] + uVar12));
      if ((uVar9 == local_38) ||
         (iVar4 = FUN_08010cd6(local_34,*(undefined1 *)(auStack_58[3] + uVar12)),
         iVar4 == auStack_58[4])) {
        uVar13 = uVar13 + 1;
      }
      else {
        uVar15 = uVar15 - 1;
        puVar6[uVar13] = puVar6[uVar15];
        puVar16[uVar13] = puVar16[uVar15];
      }
    }
  }
  if (uVar15 == 1) {
LAB_080229f6:
    FUN_08021b24(uVar11);
    uVar14 = 0xffffffff;
    uVar13 = uVar12 + 1;
LAB_08022aac:
    uVar10 = *puVar6;
    uVar15 = *(uint *)(local_44 + local_40 * 8);
    puVar17 = (undefined1 *)(*(int *)(param_8 + uVar10 * 4) + uVar13);
    for (; uVar13 < uVar15; uVar13 = uVar13 + 1) {
      local_30 = uVar11;
      local_2c = uVar14;
      iVar4 = FUN_08012ee0(&local_30,&param_5);
      uVar11 = local_30;
      uVar14 = local_2c;
      if (iVar4 == 0) goto LAB_08022ae0;
      iVar4 = FUN_08010cdc(local_34,*puVar17);
      uVar3 = FUN_08012e9c(&local_30);
      uVar11 = local_30;
      iVar5 = FUN_08010cdc(local_34,uVar3);
      if (iVar4 != iVar5) {
        iVar4 = FUN_08010cd6(local_34,*puVar17);
        uVar3 = FUN_08012e9c(&local_30);
        uVar14 = local_2c;
        uVar11 = local_30;
        iVar5 = FUN_08010cd6(local_34,uVar3);
        if (iVar4 != iVar5) goto LAB_08022ae0;
      }
      FUN_08021b24(uVar11);
      uVar14 = 0xffffffff;
      puVar17 = puVar17 + 1;
    }
    if (uVar13 == uVar15) {
      *param_7 = uVar10;
      goto LAB_08022be6;
    }
  }
LAB_08022ae0:
  *param_11 = *param_11 | 4;
LAB_08022be6:
  *local_3c = uVar11;
  local_3c[1] = uVar14;
  return local_3c;
}

