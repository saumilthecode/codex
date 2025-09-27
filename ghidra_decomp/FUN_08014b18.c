
undefined4 *
FUN_08014b18(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,short *param_9)

{
  char cVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  uint uVar7;
  short sVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  undefined4 uVar12;
  uint uVar13;
  uint uVar14;
  bool bVar15;
  undefined4 local_54;
  uint local_4c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c [2];
  
  iVar4 = param_7;
  local_38 = param_3;
  local_34 = param_4;
  iVar2 = FUN_0801139c(param_7 + 0x6c);
  uVar9 = *(uint *)(iVar4 + 0xc) & 0x4a;
  if (uVar9 == 0x40) {
    uVar14 = 8;
  }
  else if (uVar9 == 8) {
    uVar14 = 0x10;
  }
  else {
    uVar14 = 10;
  }
  uVar3 = FUN_08012eba(&local_38,&param_5);
  if (uVar3 == 0) {
    cVar1 = FUN_08012e9c(&local_38);
    if ((*(char *)(iVar2 + 0x4a) == cVar1) || (*(char *)(iVar2 + 0x4b) == cVar1)) {
      bVar15 = *(char *)(iVar2 + 0x4a) == cVar1;
      if (((*(char *)(iVar2 + 0x10) == '\0') || (*(char *)(iVar2 + 0x25) != cVar1)) &&
         (*(char *)(iVar2 + 0x24) != cVar1)) {
        FUN_08010bc6(local_38);
        local_34 = 0xffffffff;
        iVar4 = FUN_08012ee0(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar10 = 0;
          uVar11 = 0;
          uVar13 = 1;
          goto LAB_08014bc0;
        }
        cVar1 = FUN_08012e9c(&local_38);
      }
    }
    else {
      bVar15 = false;
    }
    uVar10 = 0;
    uVar11 = 0;
    do {
      uVar12 = local_38;
      if (((*(char *)(iVar2 + 0x10) != '\0') && (uVar13 = uVar3, *(char *)(iVar2 + 0x25) == cVar1))
         || (uVar13 = uVar3, *(char *)(iVar2 + 0x24) == cVar1)) break;
      if (*(char *)(iVar2 + 0x4e) == cVar1) {
        if (uVar10 == 0) {
          if (uVar9 != 0) {
            if (uVar14 != 8) goto LAB_08014ca6;
            uVar11 = 0;
LAB_08014ca8:
            uVar10 = 1;
            goto LAB_08014ccc;
          }
          uVar10 = 1;
        }
        else {
          if (uVar14 != 10) goto LAB_08014cb0;
          if (uVar9 != 0) {
LAB_08014ca6:
            uVar11 = uVar11 + 1;
            goto LAB_08014ca8;
          }
        }
        uVar14 = 8;
        uVar11 = uVar9;
      }
      else {
        uVar13 = uVar10;
        if (uVar10 == 0) break;
LAB_08014cb0:
        if ((*(char *)(iVar2 + 0x4c) != cVar1) && (*(char *)(iVar2 + 0x4d) != cVar1)) {
          uVar10 = 1;
          uVar13 = uVar3;
          break;
        }
        if (uVar9 == 0) {
          uVar14 = 0x10;
          uVar10 = 0;
          uVar11 = uVar9;
        }
        else {
          if (uVar14 != 0x10) {
            uVar10 = 1;
            uVar13 = uVar3;
            local_4c = uVar14;
            goto LAB_08014bcc;
          }
          uVar10 = 0;
          uVar11 = 0;
        }
      }
LAB_08014ccc:
      FUN_08010bc6(local_38);
      local_34 = 0xffffffff;
      local_38 = uVar12;
      iVar4 = FUN_08012ee0(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar13 = 1;
        break;
      }
      cVar1 = FUN_08012e9c(&local_38);
      uVar13 = uVar10;
    } while (uVar10 != 0);
  }
  else {
    cVar1 = '\0';
    bVar15 = false;
    uVar11 = 0;
    uVar10 = 0;
    uVar13 = uVar3;
  }
LAB_08014bc0:
  local_4c = uVar14;
  if (uVar14 == 0x10) {
    local_4c = 0x16;
  }
LAB_08014bcc:
  local_54 = local_34;
  uVar12 = local_38;
  local_2c[0] = DAT_08014e70;
  if (*(char *)(iVar2 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar6 = (uint)*(byte *)(iVar2 + 100);
  uVar3 = uVar13;
  uVar9 = uVar13;
  if (uVar6 == 0) {
    if (uVar13 == 0) {
      while (iVar4 = FUN_08010bda(local_4c,cVar1), iVar4 != -1) {
        if (0xffff / uVar14 < uVar3) {
          uVar9 = 1;
        }
        else {
          uVar3 = (int)(short)uVar14 * (int)(short)uVar3 & 0xffff;
          if (0xffff - iVar4 < (int)uVar3) {
            uVar9 = uVar9 | 1;
          }
          uVar3 = uVar3 + iVar4 & 0xffff;
          uVar11 = uVar11 + 1;
        }
        FUN_08010bc6(uVar12);
        local_34 = 0xffffffff;
        local_38 = uVar12;
        iVar4 = FUN_08012ee0(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar13 = 1;
          local_54 = local_34;
          uVar7 = 0;
          uVar12 = local_38;
          goto LAB_08014da4;
        }
        cVar1 = FUN_08012e9c(&local_38);
        local_54 = local_34;
        uVar12 = local_38;
      }
      goto LAB_08014e60;
    }
    uVar7 = 0;
    uVar3 = 0;
    uVar9 = uVar6;
  }
  else if (uVar13 == 0) {
    while( true ) {
      uVar7 = (uint)*(byte *)(iVar2 + 0x10);
      if ((uVar7 == 0) || (*(char *)(iVar2 + 0x25) != cVar1)) {
        if (*(char *)(iVar2 + 0x24) == cVar1) goto LAB_08014e60;
        iVar4 = FUN_08010cc6(iVar2 + 0x4e,local_4c);
        if (iVar4 == 0) {
          uVar7 = 0;
          goto LAB_08014da4;
        }
        iVar4 = iVar4 - (iVar2 + 0x4e);
        if (0xf < iVar4) {
          iVar4 = iVar4 + -6;
        }
        uVar7 = uVar6;
        if (uVar3 <= 0xffff / uVar14) {
          uVar3 = (int)(short)uVar14 * (int)(short)uVar3 & 0xffff;
          if (0xffff - iVar4 < (int)uVar3) {
            uVar9 = uVar9 | 1;
          }
          uVar3 = uVar3 + iVar4 & 0xffff;
          uVar11 = uVar11 + 1;
          uVar7 = uVar9;
        }
      }
      else {
        if (uVar11 == 0) goto LAB_08014da4;
        FUN_0800ac3e(local_2c,uVar11 & 0xff);
        uVar11 = 0;
        uVar7 = uVar9;
      }
      FUN_08010bc6(uVar12);
      local_34 = 0xffffffff;
      local_38 = uVar12;
      iVar4 = FUN_08012ee0(&local_38,&param_5);
      uVar9 = uVar7;
      if (iVar4 == 0) break;
      cVar1 = FUN_08012e9c(&local_38);
      local_54 = local_34;
      uVar12 = local_38;
    }
    local_54 = local_34;
    uVar7 = 0;
    uVar12 = local_38;
    uVar13 = uVar6;
  }
  else {
    uVar3 = 0;
    uVar9 = 0;
LAB_08014e60:
    uVar7 = 0;
  }
LAB_08014da4:
  sVar8 = (short)uVar3;
  iVar4 = FUN_08010c1a(local_2c[0]);
  if (iVar4 != 0) {
    FUN_0800ac3e(local_2c,uVar11 & 0xff);
    iVar4 = FUN_0801fbd4(*(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc),local_2c);
    if (iVar4 == 0) {
      *param_8 = 4;
    }
  }
  uVar5 = local_2c[0];
  if ((((uVar11 == 0) && (uVar10 == 0)) && (iVar4 = FUN_08010c1a(local_2c[0]), iVar4 == 0)) ||
     (uVar7 != 0)) {
    sVar8 = 0;
  }
  else {
    if (uVar9 == 0) {
      if (bVar15) {
        sVar8 = -sVar8;
      }
      *param_9 = sVar8;
      goto LAB_08014e84;
    }
    sVar8 = -1;
  }
  *param_9 = sVar8;
  *param_8 = 4;
LAB_08014e84:
  if (uVar13 != 0) {
    *param_8 = *param_8 | 2;
  }
  *param_1 = uVar12;
  param_1[1] = local_54;
  FUN_08010c74(uVar5);
  return param_1;
}

