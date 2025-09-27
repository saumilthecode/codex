
undefined4 *
FUN_08015b0c(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,uint *param_9)

{
  char cVar1;
  int iVar2;
  uint uVar3;
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
  
  iVar4 = param_7;
  local_38 = param_3;
  local_34 = param_4;
  iVar2 = FUN_0801139c(param_7 + 0x6c);
  uVar10 = *(uint *)(iVar4 + 0xc) & 0x4a;
  if (uVar10 == 0x40) {
    uVar16 = 8;
  }
  else if (uVar10 == 8) {
    uVar16 = 0x10;
  }
  else {
    uVar16 = 10;
  }
  uVar3 = FUN_08012eba(&local_38,&param_5);
  if (uVar3 == 0) {
    cVar1 = FUN_08012e9c(&local_38);
    if ((*(char *)(iVar2 + 0x4a) == cVar1) || (*(char *)(iVar2 + 0x4b) == cVar1)) {
      bVar17 = *(char *)(iVar2 + 0x4a) == cVar1;
      if (((*(char *)(iVar2 + 0x10) == '\0') || (*(char *)(iVar2 + 0x25) != cVar1)) &&
         (*(char *)(iVar2 + 0x24) != cVar1)) {
        FUN_08010bc6(local_38);
        local_34 = 0xffffffff;
        iVar4 = FUN_08012ee0(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar13 = 0;
          uVar14 = 0;
          uVar15 = 1;
          goto LAB_08015bb6;
        }
        cVar1 = FUN_08012e9c(&local_38);
      }
    }
    else {
      bVar17 = false;
    }
    uVar13 = 0;
    uVar14 = 0;
    do {
      uVar6 = local_38;
      if (((*(char *)(iVar2 + 0x10) != '\0') && (uVar15 = uVar3, *(char *)(iVar2 + 0x25) == cVar1))
         || (uVar15 = uVar3, *(char *)(iVar2 + 0x24) == cVar1)) break;
      if (*(char *)(iVar2 + 0x4e) == cVar1) {
        if (uVar13 == 0) {
          if (uVar10 != 0) {
            if (uVar16 != 8) goto LAB_08015cb2;
            uVar14 = 0;
LAB_08015cb6:
            uVar13 = 1;
            goto LAB_08015cdc;
          }
          uVar13 = 1;
        }
        else {
          if (uVar16 != 10) goto LAB_08015cbe;
          if (uVar10 != 0) {
LAB_08015cb2:
            uVar14 = uVar14 + 1;
            goto LAB_08015cb6;
          }
        }
        uVar16 = 8;
        uVar14 = uVar10;
      }
      else {
        uVar15 = uVar13;
        if (uVar13 == 0) break;
LAB_08015cbe:
        if ((*(char *)(iVar2 + 0x4c) != cVar1) && (*(char *)(iVar2 + 0x4d) != cVar1)) {
          uVar13 = 1;
          uVar15 = uVar3;
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
            uVar15 = uVar3;
            local_50 = uVar16;
            goto LAB_08015bc2;
          }
          uVar13 = 0;
          uVar14 = 0;
        }
      }
LAB_08015cdc:
      FUN_08010bc6(local_38);
      local_34 = 0xffffffff;
      local_38 = uVar6;
      iVar4 = FUN_08012ee0(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar15 = 1;
        break;
      }
      cVar1 = FUN_08012e9c(&local_38);
      uVar15 = uVar13;
    } while (uVar13 != 0);
  }
  else {
    cVar1 = '\0';
    bVar17 = false;
    uVar14 = 0;
    uVar13 = 0;
    uVar15 = uVar3;
  }
LAB_08015bb6:
  local_50 = uVar16;
  if (uVar16 == 0x10) {
    local_50 = 0x16;
  }
LAB_08015bc2:
  local_58 = local_34;
  local_60 = local_38;
  local_2c[0] = DAT_08015e44;
  if (*(char *)(iVar2 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar18 = FUN_08006980(0xffffffff,0xffffffff,uVar16,0);
  uVar5 = (uint)((ulonglong)uVar18 >> 0x20);
  uVar7 = (uint)*(byte *)(iVar2 + 100);
  uVar3 = uVar15;
  uVar10 = uVar15;
  local_5c = uVar15;
  if (uVar7 == 0) {
    if (uVar15 == 0) {
      while (uVar7 = FUN_08010bda(local_50,cVar1), uVar7 != 0xffffffff) {
        if (uVar10 < uVar5 || uVar5 - uVar10 < (uint)(uVar3 <= (uint)uVar18)) {
          uVar11 = (uint)((ulonglong)uVar16 * (ulonglong)uVar3);
          uVar8 = uVar16 * uVar10 + (int)((ulonglong)uVar16 * (ulonglong)uVar3 >> 0x20);
          uVar10 = (int)uVar7 >> 0x1f;
          local_5c = local_5c |
                     (CARRY4(uVar10,uVar8) || CARRY4(uVar10 + uVar8,(uint)CARRY4(uVar7,uVar11)));
          uVar3 = uVar7 + uVar11;
          uVar10 = uVar10 + uVar8 + CARRY4(uVar7,uVar11);
          uVar14 = uVar14 + 1;
        }
        else {
          local_5c = 1;
        }
        FUN_08010bc6(local_60);
        local_38 = local_60;
        local_34 = 0xffffffff;
        iVar4 = FUN_08012ee0(&local_38,&param_5);
        if (iVar4 == 0) {
          local_60 = local_38;
          local_58 = local_34;
          uVar15 = 1;
          uVar8 = 0;
          goto LAB_08015dd2;
        }
        cVar1 = FUN_08012e9c(&local_38);
        local_60 = local_38;
        local_58 = local_34;
      }
      goto LAB_08015ebe;
    }
    uVar8 = 0;
    uVar3 = 0;
    uVar10 = 0;
    local_5c = uVar7;
  }
  else if (uVar15 == 0) {
    while( true ) {
      uVar8 = (uint)*(byte *)(iVar2 + 0x10);
      if ((uVar8 == 0) || (*(char *)(iVar2 + 0x25) != cVar1)) {
        if (*(char *)(iVar2 + 0x24) == cVar1) goto LAB_08015ebe;
        iVar4 = FUN_08010cc6(iVar2 + 0x4e,local_50,cVar1);
        if (iVar4 == 0) {
          uVar8 = 0;
          goto LAB_08015dd2;
        }
        uVar8 = iVar4 - (iVar2 + 0x4e);
        if (0xf < (int)uVar8) {
          uVar8 = uVar8 - 6;
        }
        uVar11 = uVar7;
        if (uVar10 < uVar5 || uVar5 - uVar10 < (uint)(uVar3 <= (uint)uVar18)) {
          uVar12 = (uint)((ulonglong)uVar16 * (ulonglong)uVar3);
          uVar9 = uVar16 * uVar10 + (int)((ulonglong)uVar16 * (ulonglong)uVar3 >> 0x20);
          uVar11 = (int)uVar8 >> 0x1f;
          uVar3 = uVar8 + uVar12;
          uVar10 = uVar11 + uVar9 + CARRY4(uVar8,uVar12);
          uVar14 = uVar14 + 1;
          uVar11 = local_5c |
                   (CARRY4(uVar11,uVar9) || CARRY4(uVar11 + uVar9,(uint)CARRY4(uVar8,uVar12)));
        }
      }
      else {
        if (uVar14 == 0) goto LAB_08015dd2;
        FUN_0800ac3e(local_2c,uVar14 & 0xff);
        uVar14 = 0;
        uVar11 = local_5c;
      }
      local_5c = uVar11;
      FUN_08010bc6(local_60);
      local_38 = local_60;
      local_34 = 0xffffffff;
      iVar4 = FUN_08012ee0(&local_38,&param_5);
      if (iVar4 == 0) break;
      cVar1 = FUN_08012e9c(&local_38);
      local_60 = local_38;
      local_58 = local_34;
    }
    local_60 = local_38;
    local_58 = local_34;
    uVar8 = 0;
    uVar15 = uVar7;
  }
  else {
    uVar3 = 0;
    uVar10 = 0;
    local_5c = 0;
LAB_08015ebe:
    uVar8 = 0;
  }
LAB_08015dd2:
  iVar4 = FUN_08010c1a(local_2c[0]);
  if (iVar4 != 0) {
    FUN_0800ac3e(local_2c,uVar14 & 0xff);
    iVar4 = FUN_0801fbd4(*(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc),local_2c);
    if (iVar4 == 0) {
      *param_8 = 4;
    }
  }
  uVar6 = local_2c[0];
  if ((((uVar14 == 0) && (uVar13 == 0)) && (iVar4 = FUN_08010c1a(local_2c[0]), iVar4 == 0)) ||
     (uVar8 != 0)) {
    uVar10 = 0;
    uVar16 = 0;
  }
  else {
    if (local_5c == 0) {
      if (bVar17) {
        bVar17 = uVar3 != 0;
        uVar3 = -uVar3;
        uVar10 = -uVar10 - (uint)bVar17;
      }
      *param_9 = uVar3;
      param_9[1] = uVar10;
      goto LAB_08015ee0;
    }
    uVar10 = 0xffffffff;
    uVar16 = 0xffffffff;
  }
  *param_9 = uVar10;
  param_9[1] = uVar16;
  *param_8 = 4;
LAB_08015ee0:
  if (uVar15 != 0) {
    *param_8 = *param_8 | 2;
  }
  *param_1 = local_60;
  param_1[1] = local_58;
  FUN_08010c74(uVar6);
  return param_1;
}

