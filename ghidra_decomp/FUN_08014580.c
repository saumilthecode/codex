
undefined4 *
FUN_08014580(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,uint *param_9)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  undefined4 uVar12;
  uint uVar13;
  uint uVar14;
  undefined4 local_58;
  uint local_50;
  uint local_48;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c [2];
  
  iVar4 = param_7;
  local_38 = param_3;
  local_34 = param_4;
  iVar2 = FUN_0801139c(param_7 + 0x6c);
  uVar10 = *(uint *)(iVar4 + 0xc) & 0x4a;
  if (uVar10 == 0x40) {
    uVar14 = 8;
  }
  else if (uVar10 == 8) {
    uVar14 = 0x10;
  }
  else {
    uVar14 = 10;
  }
  uVar3 = FUN_08012eba(&local_38,&param_5);
  if (uVar3 == 0) {
    cVar1 = FUN_08012e9c(&local_38);
    if ((*(char *)(iVar2 + 0x4a) == cVar1) || (*(char *)(iVar2 + 0x4b) == cVar1)) {
      local_50 = (uint)(*(char *)(iVar2 + 0x4a) == cVar1);
      if (((*(char *)(iVar2 + 0x10) == '\0') || (*(char *)(iVar2 + 0x25) != cVar1)) &&
         (*(char *)(iVar2 + 0x24) != cVar1)) {
        FUN_08010bc6(local_38);
        local_34 = 0xffffffff;
        iVar4 = FUN_08012ee0(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar9 = 0;
          uVar11 = 0;
          uVar13 = 1;
          goto LAB_08014628;
        }
        cVar1 = FUN_08012e9c(&local_38);
      }
    }
    else {
      local_50 = 0;
    }
    uVar9 = 0;
    uVar11 = 0;
    do {
      uVar12 = local_38;
      if (((*(char *)(iVar2 + 0x10) != '\0') && (uVar13 = uVar3, *(char *)(iVar2 + 0x25) == cVar1))
         || (uVar13 = uVar3, *(char *)(iVar2 + 0x24) == cVar1)) break;
      if (*(char *)(iVar2 + 0x4e) == cVar1) {
        if (uVar9 == 0) {
          if (uVar10 != 0) {
            if (uVar14 != 8) goto LAB_08014714;
            uVar11 = 0;
LAB_08014716:
            uVar9 = 1;
            goto LAB_0801473a;
          }
          uVar9 = 1;
        }
        else {
          if (uVar14 != 10) goto LAB_0801471e;
          if (uVar10 != 0) {
LAB_08014714:
            uVar11 = uVar11 + 1;
            goto LAB_08014716;
          }
        }
        uVar14 = 8;
        uVar11 = uVar10;
      }
      else {
        uVar13 = uVar9;
        if (uVar9 == 0) break;
LAB_0801471e:
        if ((*(char *)(iVar2 + 0x4c) != cVar1) && (*(char *)(iVar2 + 0x4d) != cVar1)) {
          uVar9 = 1;
          uVar13 = uVar3;
          break;
        }
        if (uVar10 == 0) {
          uVar14 = 0x10;
          uVar9 = 0;
          uVar11 = uVar10;
        }
        else {
          if (uVar14 != 0x10) {
            uVar9 = 1;
            uVar13 = uVar3;
            local_48 = uVar14;
            goto LAB_08014634;
          }
          uVar9 = 0;
          uVar11 = 0;
        }
      }
LAB_0801473a:
      FUN_08010bc6(local_38);
      local_34 = 0xffffffff;
      local_38 = uVar12;
      iVar4 = FUN_08012ee0(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar13 = 1;
        break;
      }
      cVar1 = FUN_08012e9c(&local_38);
      uVar13 = uVar9;
    } while (uVar9 != 0);
  }
  else {
    cVar1 = '\0';
    local_50 = 0;
    uVar11 = 0;
    uVar9 = 0;
    uVar13 = uVar3;
  }
LAB_08014628:
  local_48 = uVar14;
  if (uVar14 == 0x10) {
    local_48 = 0x16;
  }
LAB_08014634:
  local_58 = local_34;
  uVar12 = local_38;
  local_2c[0] = DAT_080148d0;
  if (*(char *)(iVar2 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar6 = local_50 + 0x7fffffff;
  uVar7 = (uint)*(byte *)(iVar2 + 100);
  uVar3 = uVar13;
  uVar10 = uVar13;
  if (uVar7 == 0) {
    if (uVar13 == 0) {
      while (iVar4 = FUN_08010bda(local_48,cVar1), iVar4 != -1) {
        if (uVar6 / uVar14 < uVar3) {
          uVar10 = 1;
        }
        else {
          if (uVar6 - iVar4 < uVar3 * uVar14) {
            uVar10 = uVar10 | 1;
          }
          uVar11 = uVar11 + 1;
          uVar3 = uVar3 * uVar14 + iVar4;
        }
        FUN_08010bc6(uVar12);
        local_34 = 0xffffffff;
        local_38 = uVar12;
        iVar4 = FUN_08012ee0(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar13 = 1;
          local_58 = local_34;
          uVar8 = 0;
          uVar12 = local_38;
          goto LAB_08014808;
        }
        cVar1 = FUN_08012e9c(&local_38);
        local_58 = local_34;
        uVar12 = local_38;
      }
      goto LAB_080148bc;
    }
    uVar8 = 0;
    uVar3 = 0;
    uVar10 = uVar7;
  }
  else if (uVar13 == 0) {
    while( true ) {
      uVar8 = (uint)*(byte *)(iVar2 + 0x10);
      if ((uVar8 == 0) || (*(char *)(iVar2 + 0x25) != cVar1)) {
        if (*(char *)(iVar2 + 0x24) == cVar1) goto LAB_080148bc;
        iVar4 = FUN_08010cc6(iVar2 + 0x4e,local_48);
        if (iVar4 == 0) {
          uVar8 = 0;
          goto LAB_08014808;
        }
        iVar4 = iVar4 - (iVar2 + 0x4e);
        if (0xf < iVar4) {
          iVar4 = iVar4 + -6;
        }
        uVar8 = uVar7;
        if (uVar3 <= uVar6 / uVar14) {
          if (uVar6 - iVar4 < uVar3 * uVar14) {
            uVar10 = uVar10 | 1;
          }
          uVar11 = uVar11 + 1;
          uVar3 = uVar3 * uVar14 + iVar4;
          uVar8 = uVar10;
        }
      }
      else {
        if (uVar11 == 0) goto LAB_08014808;
        FUN_0800ac3e(local_2c,uVar11 & 0xff);
        uVar11 = 0;
        uVar8 = uVar10;
      }
      FUN_08010bc6(uVar12);
      local_34 = 0xffffffff;
      local_38 = uVar12;
      iVar4 = FUN_08012ee0(&local_38,&param_5);
      uVar10 = uVar8;
      if (iVar4 == 0) break;
      cVar1 = FUN_08012e9c(&local_38);
      local_58 = local_34;
      uVar12 = local_38;
    }
    local_58 = local_34;
    uVar8 = 0;
    uVar12 = local_38;
    uVar13 = uVar7;
  }
  else {
    uVar3 = 0;
    uVar10 = 0;
LAB_080148bc:
    uVar8 = 0;
  }
LAB_08014808:
  iVar4 = FUN_08010c1a(local_2c[0]);
  if (iVar4 != 0) {
    FUN_0800ac3e(local_2c,uVar11 & 0xff);
    iVar4 = FUN_0801fbd4(*(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc),local_2c);
    if (iVar4 == 0) {
      *param_8 = 4;
    }
  }
  uVar5 = local_2c[0];
  if ((((uVar11 == 0) && (uVar9 == 0)) && (iVar4 = FUN_08010c1a(local_2c[0]), iVar4 == 0)) ||
     (uVar8 != 0)) {
    uVar10 = 0;
  }
  else {
    if (uVar10 == 0) {
      if (local_50 != 0) {
        uVar3 = -uVar3;
      }
      *param_9 = uVar3;
      goto LAB_080148e0;
    }
    uVar10 = ~(-local_50 ^ 0x80000000);
  }
  *param_9 = uVar10;
  *param_8 = 4;
LAB_080148e0:
  if (uVar13 != 0) {
    *param_8 = *param_8 | 2;
  }
  *param_1 = uVar12;
  param_1[1] = local_58;
  FUN_08010c74(uVar5);
  return param_1;
}

