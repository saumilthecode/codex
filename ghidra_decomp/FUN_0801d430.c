
undefined4 *
FUN_0801d430(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,uint *param_9)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  uint uVar16;
  bool bVar17;
  undefined8 uVar18;
  undefined4 local_60;
  uint local_5c;
  undefined4 local_58;
  uint local_50;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c [2];
  
  iVar3 = param_7;
  local_38 = param_3;
  local_34 = param_4;
  iVar1 = FUN_08018fd4(param_7 + 0x6c);
  uVar10 = *(uint *)(iVar3 + 0xc) & 0x4a;
  if (uVar10 == 0x40) {
    uVar16 = 8;
  }
  else if (uVar10 == 8) {
    uVar16 = 0x10;
  }
  else {
    uVar16 = 10;
  }
  uVar2 = FUN_0800e0d6(&local_38,&param_5);
  if (uVar2 == 0) {
    iVar3 = FUN_0800e0b8(&local_38);
    if ((*(int *)(iVar1 + 0xbc) == iVar3) || (*(int *)(iVar1 + 0xc0) == iVar3)) {
      bVar17 = *(int *)(iVar1 + 0xbc) == iVar3;
      if (((*(char *)(iVar1 + 0x10) == '\0') || (*(int *)(iVar1 + 0x28) != iVar3)) &&
         (*(int *)(iVar1 + 0x24) != iVar3)) {
        FUN_080187b2(local_38);
        local_34 = 0xffffffff;
        iVar4 = FUN_0800e0fc(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar13 = 0;
          uVar14 = 0;
          uVar15 = 1;
          goto LAB_0801d4d6;
        }
        iVar3 = FUN_0800e0b8(&local_38);
      }
    }
    else {
      bVar17 = false;
    }
    uVar13 = 0;
    uVar14 = 0;
    do {
      uVar6 = local_38;
      if (((*(char *)(iVar1 + 0x10) != '\0') && (uVar15 = uVar2, *(int *)(iVar1 + 0x28) == iVar3))
         || (uVar15 = uVar2, *(int *)(iVar1 + 0x24) == iVar3)) break;
      if (*(int *)(iVar1 + 0xcc) == iVar3) {
        if (uVar13 == 0) {
          if (uVar10 != 0) {
            if (uVar16 != 8) goto LAB_0801d5cc;
            uVar14 = 0;
LAB_0801d5d0:
            uVar13 = 1;
            goto LAB_0801d5f6;
          }
          uVar13 = 1;
        }
        else {
          if (uVar16 != 10) goto LAB_0801d5d8;
          if (uVar10 != 0) {
LAB_0801d5cc:
            uVar14 = uVar14 + 1;
            goto LAB_0801d5d0;
          }
        }
        uVar16 = 8;
        uVar14 = uVar10;
      }
      else {
        uVar15 = uVar13;
        if (uVar13 == 0) break;
LAB_0801d5d8:
        if ((*(int *)(iVar1 + 0xc4) != iVar3) && (*(int *)(iVar1 + 200) != iVar3)) {
          uVar13 = 1;
          uVar15 = uVar2;
          break;
        }
        if (uVar10 == 0) {
          uVar16 = 0x10;
          uVar13 = 0;
          uVar14 = uVar10;
        }
        else {
          if (uVar16 != 0x10) {
            uVar13 = 1;
            uVar15 = uVar2;
            local_50 = uVar16;
            goto LAB_0801d4e2;
          }
          uVar13 = 0;
          uVar14 = 0;
        }
      }
LAB_0801d5f6:
      FUN_080187b2(local_38);
      local_34 = 0xffffffff;
      local_38 = uVar6;
      iVar4 = FUN_0800e0fc(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar15 = 1;
        break;
      }
      iVar3 = FUN_0800e0b8(&local_38);
      uVar15 = uVar13;
    } while (uVar13 != 0);
  }
  else {
    bVar17 = false;
    iVar3 = 0;
    uVar14 = 0;
    uVar13 = 0;
    uVar15 = uVar2;
  }
LAB_0801d4d6:
  local_50 = uVar16;
  if (uVar16 == 0x10) {
    local_50 = 0x16;
  }
LAB_0801d4e2:
  local_58 = local_34;
  local_60 = local_38;
  local_2c[0] = DAT_0801d75c;
  if (*(char *)(iVar1 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar18 = FUN_08006980(0xffffffff,0xffffffff,uVar16,0);
  uVar5 = (uint)((ulonglong)uVar18 >> 0x20);
  uVar7 = (uint)*(byte *)(iVar1 + 0x124);
  uVar2 = uVar15;
  uVar10 = uVar15;
  local_5c = uVar15;
  if (uVar7 == 0) {
    if (uVar15 == 0) {
      while (uVar7 = FUN_0801882c(local_50,iVar3), uVar7 != 0xffffffff) {
        if (uVar10 < uVar5 || uVar5 - uVar10 < (uint)(uVar2 <= (uint)uVar18)) {
          uVar11 = (uint)((ulonglong)uVar16 * (ulonglong)uVar2);
          uVar8 = uVar16 * uVar10 + (int)((ulonglong)uVar16 * (ulonglong)uVar2 >> 0x20);
          uVar10 = (int)uVar7 >> 0x1f;
          local_5c = local_5c |
                     (CARRY4(uVar10,uVar8) || CARRY4(uVar10 + uVar8,(uint)CARRY4(uVar7,uVar11)));
          uVar2 = uVar7 + uVar11;
          uVar10 = uVar10 + uVar8 + CARRY4(uVar7,uVar11);
          uVar14 = uVar14 + 1;
        }
        else {
          local_5c = 1;
        }
        FUN_080187b2(local_60);
        local_38 = local_60;
        local_34 = 0xffffffff;
        iVar3 = FUN_0800e0fc(&local_38,&param_5);
        if (iVar3 == 0) {
          local_60 = local_38;
          local_58 = local_34;
          uVar15 = 1;
          uVar8 = 0;
          goto LAB_0801d6ec;
        }
        iVar3 = FUN_0800e0b8(&local_38);
        local_60 = local_38;
        local_58 = local_34;
      }
      goto LAB_0801d7da;
    }
    uVar8 = 0;
    uVar2 = 0;
    uVar10 = 0;
    local_5c = uVar7;
  }
  else if (uVar15 == 0) {
    while( true ) {
      uVar8 = (uint)*(byte *)(iVar1 + 0x10);
      if ((uVar8 == 0) || (*(int *)(iVar1 + 0x28) != iVar3)) {
        if (*(int *)(iVar1 + 0x24) == iVar3) goto LAB_0801d7da;
        uVar8 = FUN_08018960(iVar1 + 0xcc,local_50,iVar3);
        if (uVar8 == 0) goto LAB_0801d6ec;
        iVar3 = uVar8 - (iVar1 + 0xcc);
        uVar8 = iVar3 >> 2;
        if (0x3c < iVar3) {
          uVar8 = uVar8 - 6;
        }
        uVar11 = uVar7;
        if (uVar10 < uVar5 || uVar5 - uVar10 < (uint)(uVar2 <= (uint)uVar18)) {
          uVar12 = (uint)((ulonglong)uVar16 * (ulonglong)uVar2);
          uVar9 = uVar16 * uVar10 + (int)((ulonglong)uVar16 * (ulonglong)uVar2 >> 0x20);
          uVar11 = (int)uVar8 >> 0x1f;
          uVar2 = uVar8 + uVar12;
          uVar10 = uVar11 + uVar9 + CARRY4(uVar8,uVar12);
          uVar14 = uVar14 + 1;
          uVar11 = local_5c |
                   (CARRY4(uVar11,uVar9) || CARRY4(uVar11 + uVar9,(uint)CARRY4(uVar8,uVar12)));
        }
      }
      else {
        if (uVar14 == 0) goto LAB_0801d6ec;
        FUN_0800ac3e(local_2c,uVar14 & 0xff);
        uVar14 = 0;
        uVar11 = local_5c;
      }
      local_5c = uVar11;
      FUN_080187b2(local_60);
      local_38 = local_60;
      local_34 = 0xffffffff;
      iVar3 = FUN_0800e0fc(&local_38,&param_5);
      if (iVar3 == 0) break;
      iVar3 = FUN_0800e0b8(&local_38);
      local_60 = local_38;
      local_58 = local_34;
    }
    local_60 = local_38;
    local_58 = local_34;
    uVar8 = 0;
    uVar15 = uVar7;
  }
  else {
    uVar2 = 0;
    uVar10 = 0;
    local_5c = 0;
LAB_0801d7da:
    uVar8 = 0;
  }
LAB_0801d6ec:
  iVar3 = FUN_08018910(local_2c[0]);
  if (iVar3 != 0) {
    FUN_0800ac3e(local_2c,uVar14 & 0xff);
    iVar3 = FUN_0801fbd4(*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),local_2c);
    if (iVar3 == 0) {
      *param_8 = 4;
    }
  }
  uVar6 = local_2c[0];
  if ((((uVar14 == 0) && (uVar13 == 0)) && (iVar3 = FUN_08018910(local_2c[0]), iVar3 == 0)) ||
     (uVar8 != 0)) {
    uVar10 = 0;
    uVar16 = 0;
  }
  else {
    if (local_5c == 0) {
      if (bVar17) {
        bVar17 = uVar2 != 0;
        uVar2 = -uVar2;
        uVar10 = -uVar10 - (uint)bVar17;
      }
      *param_9 = uVar2;
      param_9[1] = uVar10;
      goto LAB_0801d7f8;
    }
    uVar10 = 0xffffffff;
    uVar16 = 0xffffffff;
  }
  *param_9 = uVar10;
  param_9[1] = uVar16;
  *param_8 = 4;
LAB_0801d7f8:
  if (uVar15 != 0) {
    *param_8 = *param_8 | 2;
  }
  *param_1 = local_60;
  param_1[1] = local_58;
  FUN_08018950(uVar6);
  return param_1;
}

