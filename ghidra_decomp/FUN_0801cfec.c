
undefined4 *
FUN_0801cfec(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,uint *param_9)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  undefined4 uVar13;
  uint uVar14;
  uint uVar15;
  bool bVar16;
  undefined8 uVar17;
  uint local_68;
  uint local_64;
  undefined4 local_60;
  uint local_5c;
  uint local_50;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c [2];
  
  iVar3 = param_7;
  local_38 = param_3;
  local_34 = param_4;
  iVar1 = FUN_08018fd4(param_7 + 0x6c);
  uVar9 = *(uint *)(iVar3 + 0xc) & 0x4a;
  if (uVar9 == 0x40) {
    uVar15 = 8;
  }
  else if (uVar9 == 8) {
    uVar15 = 0x10;
  }
  else {
    uVar15 = 10;
  }
  uVar2 = FUN_0800e0d6(&local_38,&param_5);
  if (uVar2 == 0) {
    iVar3 = FUN_0800e0b8(&local_38);
    if ((*(int *)(iVar1 + 0xbc) == iVar3) || (*(int *)(iVar1 + 0xc0) == iVar3)) {
      local_5c = (uint)(*(int *)(iVar1 + 0xbc) == iVar3);
      if (((*(char *)(iVar1 + 0x10) == '\0') || (*(int *)(iVar1 + 0x28) != iVar3)) &&
         (*(int *)(iVar1 + 0x24) != iVar3)) {
        FUN_080187b2(local_38);
        local_34 = 0xffffffff;
        iVar4 = FUN_0800e0fc(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar11 = 0;
          uVar12 = 0;
          uVar14 = 1;
          goto LAB_0801d08e;
        }
        iVar3 = FUN_0800e0b8(&local_38);
      }
    }
    else {
      local_5c = 0;
    }
    uVar11 = 0;
    uVar12 = 0;
    do {
      uVar13 = local_38;
      if (((*(char *)(iVar1 + 0x10) != '\0') && (uVar14 = uVar2, *(int *)(iVar1 + 0x28) == iVar3))
         || (uVar14 = uVar2, *(int *)(iVar1 + 0x24) == iVar3)) break;
      if (*(int *)(iVar1 + 0xcc) == iVar3) {
        if (uVar11 == 0) {
          if (uVar9 != 0) {
            if (uVar15 != 8) goto LAB_0801d18e;
            uVar12 = 0;
LAB_0801d192:
            uVar11 = 1;
            goto LAB_0801d1b6;
          }
          uVar11 = 1;
        }
        else {
          if (uVar15 != 10) goto LAB_0801d198;
          if (uVar9 != 0) {
LAB_0801d18e:
            uVar12 = uVar12 + 1;
            goto LAB_0801d192;
          }
        }
        uVar15 = 8;
        uVar12 = uVar9;
      }
      else {
        uVar14 = uVar11;
        if (uVar11 == 0) break;
LAB_0801d198:
        if ((*(int *)(iVar1 + 0xc4) != iVar3) && (*(int *)(iVar1 + 200) != iVar3)) {
          uVar11 = 1;
          uVar14 = uVar2;
          break;
        }
        if (uVar9 == 0) {
          uVar15 = 0x10;
          uVar11 = 0;
          uVar12 = uVar9;
        }
        else {
          if (uVar15 != 0x10) {
            uVar11 = 1;
            uVar14 = uVar2;
            local_50 = uVar15;
            goto LAB_0801d09a;
          }
          uVar11 = 0;
          uVar12 = 0;
        }
      }
LAB_0801d1b6:
      FUN_080187b2(local_38);
      local_34 = 0xffffffff;
      local_38 = uVar13;
      iVar4 = FUN_0800e0fc(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar14 = 1;
        break;
      }
      iVar3 = FUN_0800e0b8(&local_38);
      uVar14 = uVar11;
    } while (uVar11 != 0);
  }
  else {
    local_5c = 0;
    iVar3 = 0;
    uVar12 = 0;
    uVar11 = 0;
    uVar14 = uVar2;
  }
LAB_0801d08e:
  local_50 = uVar15;
  if (uVar15 == 0x10) {
    local_50 = 0x16;
  }
LAB_0801d09a:
  local_60 = local_34;
  uVar13 = local_38;
  local_2c[0] = DAT_0801d31c;
  if (*(char *)(iVar1 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar6 = local_5c - 1;
  iVar4 = local_5c + 0x7fffffff;
  uVar17 = FUN_08006980(uVar6,iVar4,uVar15,0);
  uVar2 = (uint)((ulonglong)uVar17 >> 0x20);
  uVar7 = (uint)*(byte *)(iVar1 + 0x124);
  uVar9 = uVar14;
  local_68 = uVar14;
  local_64 = uVar14;
  if (uVar7 == 0) {
    if (uVar14 == 0) {
      while (uVar7 = FUN_0801882c(local_50,iVar3), uVar7 != 0xffffffff) {
        if (local_64 < uVar2 || uVar2 - local_64 < (uint)(uVar9 <= (uint)uVar17)) {
          uVar8 = (uint)((ulonglong)uVar15 * (ulonglong)uVar9);
          local_64 = uVar15 * local_64 + (int)((ulonglong)uVar15 * (ulonglong)uVar9 >> 0x20);
          uVar9 = (iVar4 - ((int)uVar7 >> 0x1f)) - (uint)(uVar6 < uVar7);
          if (uVar9 <= local_64 && (uint)(uVar8 <= uVar6 - uVar7) <= uVar9 - local_64) {
            local_68 = local_68 | 1;
          }
          uVar9 = uVar7 + uVar8;
          local_64 = local_64 + ((int)uVar7 >> 0x1f) + (uint)CARRY4(uVar7,uVar8);
          uVar12 = uVar12 + 1;
        }
        else {
          local_68 = 1;
        }
        FUN_080187b2(uVar13);
        local_34 = 0xffffffff;
        local_38 = uVar13;
        iVar3 = FUN_0800e0fc(&local_38,&param_5);
        if (iVar3 == 0) {
          uVar14 = 1;
          local_60 = local_34;
          uVar8 = 0;
          uVar13 = local_38;
          goto LAB_0801d2a8;
        }
        iVar3 = FUN_0800e0b8(&local_38);
        local_60 = local_34;
        uVar13 = local_38;
      }
      goto LAB_0801d39a;
    }
    uVar8 = 0;
    uVar9 = 0;
    local_64 = 0;
    local_68 = uVar7;
  }
  else if (uVar14 == 0) {
    while( true ) {
      uVar8 = (uint)*(byte *)(iVar1 + 0x10);
      if ((uVar8 == 0) || (*(int *)(iVar1 + 0x28) != iVar3)) {
        if (*(int *)(iVar1 + 0x24) == iVar3) goto LAB_0801d39a;
        uVar8 = FUN_08018960(iVar1 + 0xcc,local_50,iVar3);
        if (uVar8 == 0) goto LAB_0801d2a8;
        iVar3 = uVar8 - (iVar1 + 0xcc);
        uVar8 = iVar3 >> 2;
        if (0x3c < iVar3) {
          uVar8 = uVar8 - 6;
        }
        uVar10 = uVar7;
        if (local_64 < uVar2 || uVar2 - local_64 < (uint)(uVar9 <= (uint)uVar17)) {
          uVar10 = (uint)((ulonglong)uVar15 * (ulonglong)uVar9);
          local_64 = uVar15 * local_64 + (int)((ulonglong)uVar15 * (ulonglong)uVar9 >> 0x20);
          uVar9 = (iVar4 - ((int)uVar8 >> 0x1f)) - (uint)(uVar6 < uVar8);
          if (uVar9 <= local_64 && (uint)(uVar10 <= uVar6 - uVar8) <= uVar9 - local_64) {
            local_68 = local_68 | 1;
          }
          uVar9 = uVar8 + uVar10;
          local_64 = local_64 + ((int)uVar8 >> 0x1f) + (uint)CARRY4(uVar8,uVar10);
          uVar12 = uVar12 + 1;
          uVar10 = local_68;
        }
      }
      else {
        if (uVar12 == 0) goto LAB_0801d2a8;
        FUN_0800ac3e(local_2c,uVar12 & 0xff);
        uVar12 = 0;
        uVar10 = local_68;
      }
      local_68 = uVar10;
      FUN_080187b2(uVar13);
      local_34 = 0xffffffff;
      local_38 = uVar13;
      iVar3 = FUN_0800e0fc(&local_38,&param_5);
      if (iVar3 == 0) break;
      iVar3 = FUN_0800e0b8(&local_38);
      local_60 = local_34;
      uVar13 = local_38;
    }
    local_60 = local_34;
    uVar8 = 0;
    uVar13 = local_38;
    uVar14 = uVar7;
  }
  else {
    uVar9 = 0;
    local_68 = 0;
    local_64 = 0;
LAB_0801d39a:
    uVar8 = 0;
  }
LAB_0801d2a8:
  iVar3 = FUN_08018910(local_2c[0]);
  if (iVar3 != 0) {
    FUN_0800ac3e(local_2c,uVar12 & 0xff);
    iVar3 = FUN_0801fbd4(*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),local_2c);
    if (iVar3 == 0) {
      *param_8 = 4;
    }
  }
  uVar5 = local_2c[0];
  if ((((uVar12 == 0) && (uVar11 == 0)) && (iVar3 = FUN_08018910(local_2c[0]), iVar3 == 0)) ||
     (uVar8 != 0)) {
    *param_9 = 0;
    param_9[1] = 0;
  }
  else {
    if (local_68 == 0) {
      if (local_5c != 0) {
        bVar16 = uVar9 != 0;
        uVar9 = -uVar9;
        local_64 = -local_64 - (uint)bVar16;
      }
      *param_9 = uVar9;
      param_9[1] = local_64;
      goto LAB_0801d3b8;
    }
    *param_9 = local_5c - 1;
    param_9[1] = ~(-local_5c ^ 0x80000000);
  }
  *param_8 = 4;
LAB_0801d3b8:
  if (uVar14 != 0) {
    *param_8 = *param_8 | 2;
  }
  *param_1 = uVar13;
  param_1[1] = local_60;
  FUN_08018950(uVar5);
  return param_1;
}

