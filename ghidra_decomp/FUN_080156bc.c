
undefined4 *
FUN_080156bc(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,uint *param_9)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  undefined4 uVar14;
  uint uVar15;
  uint uVar16;
  bool bVar17;
  undefined8 uVar18;
  uint local_68;
  uint local_64;
  undefined4 local_60;
  uint local_5c;
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
      local_5c = (uint)(*(char *)(iVar2 + 0x4a) == cVar1);
      if (((*(char *)(iVar2 + 0x10) == '\0') || (*(char *)(iVar2 + 0x25) != cVar1)) &&
         (*(char *)(iVar2 + 0x24) != cVar1)) {
        FUN_08010bc6(local_38);
        local_34 = 0xffffffff;
        iVar4 = FUN_08012ee0(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar12 = 0;
          uVar13 = 0;
          uVar15 = 1;
          goto LAB_08015762;
        }
        cVar1 = FUN_08012e9c(&local_38);
      }
    }
    else {
      local_5c = 0;
    }
    uVar12 = 0;
    uVar13 = 0;
    do {
      uVar14 = local_38;
      if (((*(char *)(iVar2 + 0x10) != '\0') && (uVar15 = uVar3, *(char *)(iVar2 + 0x25) == cVar1))
         || (uVar15 = uVar3, *(char *)(iVar2 + 0x24) == cVar1)) break;
      if (*(char *)(iVar2 + 0x4e) == cVar1) {
        if (uVar12 == 0) {
          if (uVar10 != 0) {
            if (uVar16 != 8) goto LAB_08015868;
            uVar13 = 0;
LAB_0801586c:
            uVar12 = 1;
            goto LAB_08015890;
          }
          uVar12 = 1;
        }
        else {
          if (uVar16 != 10) goto LAB_08015872;
          if (uVar10 != 0) {
LAB_08015868:
            uVar13 = uVar13 + 1;
            goto LAB_0801586c;
          }
        }
        uVar16 = 8;
        uVar13 = uVar10;
      }
      else {
        uVar15 = uVar12;
        if (uVar12 == 0) break;
LAB_08015872:
        if ((*(char *)(iVar2 + 0x4c) != cVar1) && (*(char *)(iVar2 + 0x4d) != cVar1)) {
          uVar12 = 1;
          uVar15 = uVar3;
          break;
        }
        if (uVar10 == 0) {
          uVar16 = 0x10;
          uVar12 = 0;
          uVar13 = uVar10;
        }
        else {
          if (uVar16 != 0x10) {
            uVar12 = 1;
            uVar15 = uVar3;
            local_50 = uVar16;
            goto LAB_0801576e;
          }
          uVar12 = 0;
          uVar13 = 0;
        }
      }
LAB_08015890:
      FUN_08010bc6(local_38);
      local_34 = 0xffffffff;
      local_38 = uVar14;
      iVar4 = FUN_08012ee0(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar15 = 1;
        break;
      }
      cVar1 = FUN_08012e9c(&local_38);
      uVar15 = uVar12;
    } while (uVar12 != 0);
  }
  else {
    cVar1 = '\0';
    local_5c = 0;
    uVar13 = 0;
    uVar12 = 0;
    uVar15 = uVar3;
  }
LAB_08015762:
  local_50 = uVar16;
  if (uVar16 == 0x10) {
    local_50 = 0x16;
  }
LAB_0801576e:
  local_60 = local_34;
  uVar14 = local_38;
  local_2c[0] = DAT_080159f8;
  if (*(char *)(iVar2 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar7 = local_5c - 1;
  iVar4 = local_5c + 0x7fffffff;
  uVar18 = FUN_08006980(uVar7,iVar4,uVar16,0);
  uVar3 = (uint)((ulonglong)uVar18 >> 0x20);
  uVar8 = (uint)*(byte *)(iVar2 + 100);
  uVar10 = uVar15;
  local_68 = uVar15;
  local_64 = uVar15;
  if (uVar8 == 0) {
    if (uVar15 == 0) {
      while (uVar8 = FUN_08010bda(local_50,cVar1), uVar8 != 0xffffffff) {
        if (local_64 < uVar3 || uVar3 - local_64 < (uint)(uVar10 <= (uint)uVar18)) {
          uVar9 = (uint)((ulonglong)uVar16 * (ulonglong)uVar10);
          local_64 = uVar16 * local_64 + (int)((ulonglong)uVar16 * (ulonglong)uVar10 >> 0x20);
          uVar10 = (iVar4 - ((int)uVar8 >> 0x1f)) - (uint)(uVar7 < uVar8);
          if (uVar10 <= local_64 && (uint)(uVar9 <= uVar7 - uVar8) <= uVar10 - local_64) {
            local_68 = local_68 | 1;
          }
          uVar10 = uVar8 + uVar9;
          local_64 = local_64 + ((int)uVar8 >> 0x1f) + (uint)CARRY4(uVar8,uVar9);
          uVar13 = uVar13 + 1;
        }
        else {
          local_68 = 1;
        }
        FUN_08010bc6(uVar14);
        local_34 = 0xffffffff;
        local_38 = uVar14;
        iVar5 = FUN_08012ee0(&local_38,&param_5);
        if (iVar5 == 0) {
          uVar15 = 1;
          local_60 = local_34;
          uVar9 = 0;
          uVar14 = local_38;
          goto LAB_08015982;
        }
        cVar1 = FUN_08012e9c(&local_38);
        local_60 = local_34;
        uVar14 = local_38;
      }
      goto LAB_08015a72;
    }
    uVar9 = 0;
    uVar10 = 0;
    local_64 = 0;
    local_68 = uVar8;
  }
  else if (uVar15 == 0) {
    while( true ) {
      uVar9 = (uint)*(byte *)(iVar2 + 0x10);
      if ((uVar9 == 0) || (*(char *)(iVar2 + 0x25) != cVar1)) {
        if (*(char *)(iVar2 + 0x24) == cVar1) goto LAB_08015a72;
        iVar5 = FUN_08010cc6(iVar2 + 0x4e,local_50,cVar1);
        if (iVar5 == 0) {
          uVar9 = 0;
          goto LAB_08015982;
        }
        uVar9 = iVar5 - (iVar2 + 0x4e);
        if (0xf < (int)uVar9) {
          uVar9 = uVar9 - 6;
        }
        uVar11 = uVar8;
        if (local_64 < uVar3 || uVar3 - local_64 < (uint)(uVar10 <= (uint)uVar18)) {
          uVar11 = (uint)((ulonglong)uVar16 * (ulonglong)uVar10);
          local_64 = uVar16 * local_64 + (int)((ulonglong)uVar16 * (ulonglong)uVar10 >> 0x20);
          uVar10 = (iVar4 - ((int)uVar9 >> 0x1f)) - (uint)(uVar7 < uVar9);
          if (uVar10 <= local_64 && (uint)(uVar11 <= uVar7 - uVar9) <= uVar10 - local_64) {
            local_68 = local_68 | 1;
          }
          uVar10 = uVar9 + uVar11;
          local_64 = local_64 + ((int)uVar9 >> 0x1f) + (uint)CARRY4(uVar9,uVar11);
          uVar13 = uVar13 + 1;
          uVar11 = local_68;
        }
      }
      else {
        if (uVar13 == 0) goto LAB_08015982;
        FUN_0800ac3e(local_2c,uVar13 & 0xff);
        uVar13 = 0;
        uVar11 = local_68;
      }
      local_68 = uVar11;
      FUN_08010bc6(uVar14);
      local_34 = 0xffffffff;
      local_38 = uVar14;
      iVar5 = FUN_08012ee0(&local_38,&param_5);
      if (iVar5 == 0) break;
      cVar1 = FUN_08012e9c(&local_38);
      local_60 = local_34;
      uVar14 = local_38;
    }
    local_60 = local_34;
    uVar9 = 0;
    uVar14 = local_38;
    uVar15 = uVar8;
  }
  else {
    uVar10 = 0;
    local_68 = 0;
    local_64 = 0;
LAB_08015a72:
    uVar9 = 0;
  }
LAB_08015982:
  iVar4 = FUN_08010c1a(local_2c[0]);
  if (iVar4 != 0) {
    FUN_0800ac3e(local_2c,uVar13 & 0xff);
    iVar4 = FUN_0801fbd4(*(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc),local_2c);
    if (iVar4 == 0) {
      *param_8 = 4;
    }
  }
  uVar6 = local_2c[0];
  if ((((uVar13 == 0) && (uVar12 == 0)) && (iVar4 = FUN_08010c1a(local_2c[0]), iVar4 == 0)) ||
     (uVar9 != 0)) {
    *param_9 = 0;
    param_9[1] = 0;
  }
  else {
    if (local_68 == 0) {
      if (local_5c != 0) {
        bVar17 = uVar10 != 0;
        uVar10 = -uVar10;
        local_64 = -local_64 - (uint)bVar17;
      }
      *param_9 = uVar10;
      param_9[1] = local_64;
      goto LAB_08015a94;
    }
    *param_9 = local_5c - 1;
    param_9[1] = ~(-local_5c ^ 0x80000000);
  }
  *param_8 = 4;
LAB_08015a94:
  if (uVar15 != 0) {
    *param_8 = *param_8 | 2;
  }
  *param_1 = uVar14;
  param_1[1] = local_60;
  FUN_08010c74(uVar6);
  return param_1;
}

