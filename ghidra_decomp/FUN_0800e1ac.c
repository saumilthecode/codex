
undefined4 *
FUN_0800e1ac(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,uint *param_7,int param_8,uint param_9,
            int param_10,uint *param_11)

{
  bool bVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  uint *puVar7;
  uint *puVar8;
  uint uVar10;
  uint uVar11;
  undefined4 uVar12;
  undefined4 uVar13;
  uint uVar14;
  uint *puVar15;
  undefined4 *puVar16;
  uint uVar17;
  uint uVar18;
  uint local_58 [5];
  uint local_44;
  int local_40;
  undefined4 *local_3c;
  uint local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  uint *puVar9;
  
  local_3c = param_1;
  local_30 = param_3;
  local_2c = param_4;
  local_34 = FUN_08018e8c(param_10 + 0x6c);
  uVar11 = param_9;
  puVar7 = local_58 + param_9 * -2;
  local_44 = (uint)puVar7 >> 3;
  local_58[4] = param_9 << 2;
  puVar15 = puVar7 + param_9;
  iVar4 = FUN_0800e0fc(&local_30,&param_5);
  if (iVar4 == 0) {
    uVar14 = 0;
    uVar12 = local_30;
    uVar13 = local_2c;
  }
  else {
    uVar6 = FUN_0800e0b8(&local_30);
    uVar13 = local_2c;
    uVar12 = local_30;
    iVar4 = FUN_0800e0a6(local_34,uVar6);
    local_38 = FUN_0800e0ac(local_34,uVar6);
    uVar14 = 0;
    for (uVar17 = 0; uVar17 != param_9; uVar17 = uVar17 + 1) {
      iVar5 = FUN_0800e0a6(local_34,**(undefined4 **)(param_8 + uVar17 * 4));
      if ((iVar5 == iVar4) ||
         (uVar18 = FUN_0800e0ac(local_34,**(undefined4 **)(param_8 + uVar17 * 4)),
         uVar18 == local_38)) {
        local_40 = uVar14 << 2;
        uVar18 = FUN_0802698c(*(undefined4 *)(param_8 + uVar17 * 4));
        iVar5 = local_40;
        puVar15[uVar14] = uVar18;
        *(uint *)((int)puVar7 + iVar5) = uVar17;
        uVar14 = uVar14 + 1;
      }
    }
  }
  uVar17 = 0;
  while (1 < uVar14) {
    uVar18 = *puVar15;
    puVar8 = puVar15 + 1;
    do {
      puVar9 = puVar8 + 1;
      if (*puVar8 <= uVar18) {
        uVar18 = *puVar8;
      }
      puVar8 = puVar9;
    } while (puVar15 + uVar14 != puVar9);
    uVar17 = uVar17 + 1;
    FUN_0800d316(uVar12);
    if (uVar18 == uVar17) {
      local_2c = 0xffffffff;
      local_30 = uVar12;
      local_38 = FUN_0800e0fc(&local_30,&param_5);
      uVar12 = local_30;
      uVar13 = local_2c;
      if (local_38 != 0) {
        uVar13 = FUN_0800e0b8(&local_30);
        local_58[3] = FUN_0800e0a6(local_34,uVar13);
        uVar6 = FUN_0800e0b8(&local_30);
        uVar13 = local_2c;
        uVar12 = local_30;
        local_58[2] = FUN_0800e0ac(local_34,uVar6);
        local_40 = uVar18 << 2;
        uVar10 = 0;
        do {
          if (uVar18 < puVar15[uVar10]) {
            local_58[1] = *(int *)(param_8 + puVar7[uVar10] * 4);
            local_58[0] = uVar10;
            iVar4 = FUN_0800e0a6(local_34,*(undefined4 *)(local_58[1] + local_40));
            if ((iVar4 == local_58[3]) ||
               (iVar4 = FUN_0800e0ac(local_34,*(undefined4 *)(local_58[1] + local_40)),
               uVar10 = local_58[0], iVar4 == local_58[2])) goto LAB_0800e2ba;
          }
          uVar10 = uVar10 + 1;
        } while (uVar14 != uVar10);
        local_38 = 0;
      }
LAB_0800e2ba:
      uVar10 = 0;
      do {
        if ((puVar15[uVar10] == uVar18) == local_38) {
          uVar14 = uVar14 - 1;
          puVar7[uVar10] = puVar7[uVar14];
          puVar15[uVar10] = puVar15[uVar14];
        }
        else {
          uVar10 = uVar10 + 1;
        }
        uVar3 = local_44;
        uVar2 = local_58[4];
      } while (uVar10 < uVar14);
      if (local_38 != 0) {
        uVar18 = *puVar15;
        for (uVar10 = 1; uVar10 < uVar14; uVar10 = uVar10 + 1) {
          if (puVar15[uVar10] <= uVar18) {
            uVar18 = puVar15[uVar10];
          }
        }
        goto LAB_0800e2fa;
      }
      if (uVar14 == 2) {
        if ((int)(param_9 << 0x1f) < 0) goto LAB_0800e416;
        uVar14 = *puVar7;
        if (uVar14 < param_9 >> 1) {
          if (uVar14 + (param_9 >> 1) == local_58[uVar11 * -2 + 1]) goto LAB_0800e3e2;
          goto LAB_0800e416;
        }
        uVar14 = uVar14 - (param_9 >> 1);
        if (uVar14 != local_58[uVar11 * -2 + 1]) goto LAB_0800e416;
        *puVar7 = uVar14;
        *(uint *)(uVar2 + uVar3 * 8) = puVar15[1];
      }
      else {
        bVar1 = true;
LAB_0800e31a:
        if (uVar14 != 1) goto LAB_0800e416;
        uVar18 = uVar17;
        if (!bVar1) goto LAB_0800e322;
      }
      goto LAB_0800e3e2;
    }
    uVar13 = 0xffffffff;
LAB_0800e2fa:
    if (uVar18 <= uVar17) {
      bVar1 = false;
      goto LAB_0800e31a;
    }
    local_30 = uVar12;
    local_2c = uVar13;
    iVar4 = FUN_0800e0fc(&local_30,&param_5);
    if (iVar4 == 0) {
      bVar1 = false;
      uVar12 = local_30;
      uVar13 = local_2c;
      goto LAB_0800e31a;
    }
    uVar13 = FUN_0800e0b8(&local_30);
    local_40 = FUN_0800e0a6(local_34,uVar13);
    uVar6 = FUN_0800e0b8(&local_30);
    uVar13 = local_2c;
    uVar12 = local_30;
    local_58[3] = FUN_0800e0ac(local_34,uVar6);
    local_38 = uVar17 * 4;
    uVar18 = 0;
    while (uVar18 < uVar14) {
      local_58[2] = *(int *)(param_8 + puVar7[uVar18] * 4);
      iVar4 = FUN_0800e0a6(local_34,*(undefined4 *)(local_58[2] + local_38));
      if ((iVar4 == local_40) ||
         (iVar4 = FUN_0800e0ac(local_34,*(undefined4 *)(local_58[2] + local_38)),
         iVar4 == local_58[3])) {
        uVar18 = uVar18 + 1;
      }
      else {
        uVar14 = uVar14 - 1;
        puVar7[uVar18] = puVar7[uVar14];
        puVar15[uVar18] = puVar15[uVar14];
      }
    }
  }
  if (uVar14 == 1) {
LAB_0800e322:
    FUN_0800d316(uVar12);
    uVar13 = 0xffffffff;
    uVar18 = uVar17 + 1;
LAB_0800e3e2:
    uVar11 = *puVar7;
    uVar14 = *(uint *)(local_58[4] + local_44 * 8);
    puVar16 = (undefined4 *)(*(int *)(param_8 + uVar11 * 4) + uVar18 * 4);
    for (; uVar18 < uVar14; uVar18 = uVar18 + 1) {
      local_30 = uVar12;
      local_2c = uVar13;
      iVar4 = FUN_0800e0fc(&local_30,&param_5);
      uVar12 = local_30;
      uVar13 = local_2c;
      if (iVar4 == 0) goto LAB_0800e416;
      iVar4 = FUN_0800e0a6(local_34,*puVar16);
      uVar13 = FUN_0800e0b8(&local_30);
      uVar12 = local_30;
      iVar5 = FUN_0800e0a6(local_34,uVar13);
      if (iVar4 != iVar5) {
        iVar4 = FUN_0800e0ac(local_34,*puVar16);
        uVar6 = FUN_0800e0b8(&local_30);
        uVar13 = local_2c;
        uVar12 = local_30;
        iVar5 = FUN_0800e0ac(local_34,uVar6);
        if (iVar4 != iVar5) goto LAB_0800e416;
      }
      FUN_0800d316(uVar12);
      uVar13 = 0xffffffff;
      puVar16 = puVar16 + 1;
    }
    if (uVar18 == uVar14) {
      *param_7 = uVar11;
      goto LAB_0800e528;
    }
  }
LAB_0800e416:
  *param_11 = *param_11 | 4;
LAB_0800e528:
  *local_3c = uVar12;
  local_3c[1] = uVar13;
  return local_3c;
}

