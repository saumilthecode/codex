
undefined4 *
FUN_0801cbdc(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
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
  undefined4 uVar12;
  uint uVar13;
  uint uVar14;
  bool bVar15;
  undefined4 local_54;
  uint local_4c;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c [2];
  
  iVar3 = param_7;
  local_38 = param_3;
  local_34 = param_4;
  iVar1 = FUN_08018fd4(param_7 + 0x6c);
  uVar9 = *(uint *)(iVar3 + 0xc) & 0x4a;
  if (uVar9 == 0x40) {
    uVar14 = 8;
  }
  else if (uVar9 == 8) {
    uVar14 = 0x10;
  }
  else {
    uVar14 = 10;
  }
  uVar2 = FUN_0800e0d6(&local_38,&param_5);
  if (uVar2 == 0) {
    iVar3 = FUN_0800e0b8(&local_38);
    if ((*(int *)(iVar1 + 0xbc) == iVar3) || (*(int *)(iVar1 + 0xc0) == iVar3)) {
      bVar15 = *(int *)(iVar1 + 0xbc) == iVar3;
      if (((*(char *)(iVar1 + 0x10) == '\0') || (*(int *)(iVar1 + 0x28) != iVar3)) &&
         (*(int *)(iVar1 + 0x24) != iVar3)) {
        FUN_080187b2(local_38);
        local_34 = 0xffffffff;
        iVar4 = FUN_0800e0fc(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar8 = 0;
          uVar11 = 0;
          uVar13 = 1;
          goto LAB_0801cc80;
        }
        iVar3 = FUN_0800e0b8(&local_38);
      }
    }
    else {
      bVar15 = false;
    }
    uVar8 = 0;
    uVar11 = 0;
    do {
      uVar12 = local_38;
      if (((*(char *)(iVar1 + 0x10) != '\0') && (uVar13 = uVar2, *(int *)(iVar1 + 0x28) == iVar3))
         || (uVar13 = uVar2, *(int *)(iVar1 + 0x24) == iVar3)) break;
      if (*(int *)(iVar1 + 0xcc) == iVar3) {
        if (uVar8 == 0) {
          if (uVar9 != 0) {
            if (uVar14 != 8) goto LAB_0801cd60;
            uVar11 = 0;
LAB_0801cd62:
            uVar8 = 1;
            goto LAB_0801cd86;
          }
          uVar8 = 1;
        }
        else {
          if (uVar14 != 10) goto LAB_0801cd6a;
          if (uVar9 != 0) {
LAB_0801cd60:
            uVar11 = uVar11 + 1;
            goto LAB_0801cd62;
          }
        }
        uVar14 = 8;
        uVar11 = uVar9;
      }
      else {
        uVar13 = uVar8;
        if (uVar8 == 0) break;
LAB_0801cd6a:
        if ((*(int *)(iVar1 + 0xc4) != iVar3) && (*(int *)(iVar1 + 200) != iVar3)) {
          uVar8 = 1;
          uVar13 = uVar2;
          break;
        }
        if (uVar9 == 0) {
          uVar14 = 0x10;
          uVar8 = 0;
          uVar11 = uVar9;
        }
        else {
          if (uVar14 != 0x10) {
            uVar8 = 1;
            uVar13 = uVar2;
            local_4c = uVar14;
            goto LAB_0801cc8c;
          }
          uVar8 = 0;
          uVar11 = 0;
        }
      }
LAB_0801cd86:
      FUN_080187b2(local_38);
      local_34 = 0xffffffff;
      local_38 = uVar12;
      iVar4 = FUN_0800e0fc(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar13 = 1;
        break;
      }
      iVar3 = FUN_0800e0b8(&local_38);
      uVar13 = uVar8;
    } while (uVar8 != 0);
  }
  else {
    iVar3 = 0;
    bVar15 = false;
    uVar11 = 0;
    uVar8 = 0;
    uVar13 = uVar2;
  }
LAB_0801cc80:
  local_4c = uVar14;
  if (uVar14 == 0x10) {
    local_4c = 0x16;
  }
LAB_0801cc8c:
  local_54 = local_34;
  uVar12 = local_38;
  local_2c[0] = DAT_0801cf14;
  if (*(char *)(iVar1 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar6 = (uint)*(byte *)(iVar1 + 0x124);
  uVar2 = uVar13;
  uVar9 = uVar13;
  if (uVar6 == 0) {
    if (uVar13 == 0) {
      while (uVar6 = FUN_0801882c(local_4c,iVar3), uVar6 != 0xffffffff) {
        if (0xffffffff / uVar14 < uVar2) {
          uVar9 = 1;
        }
        else {
          uVar7 = uVar2 * uVar14;
          uVar2 = uVar6 + uVar7;
          if (CARRY4(uVar6,uVar7)) {
            uVar9 = uVar9 | 1;
          }
          uVar11 = uVar11 + 1;
        }
        FUN_080187b2(uVar12);
        local_34 = 0xffffffff;
        local_38 = uVar12;
        iVar3 = FUN_0800e0fc(&local_38,&param_5);
        if (iVar3 == 0) {
          uVar13 = 1;
          local_54 = local_34;
          uVar7 = 0;
          uVar12 = local_38;
          goto LAB_0801ce50;
        }
        iVar3 = FUN_0800e0b8(&local_38);
        local_54 = local_34;
        uVar12 = local_38;
      }
      goto LAB_0801cf06;
    }
    uVar7 = 0;
    uVar2 = 0;
    uVar9 = uVar6;
  }
  else if (uVar13 == 0) {
    while( true ) {
      uVar7 = (uint)*(byte *)(iVar1 + 0x10);
      if ((uVar7 == 0) || (*(int *)(iVar1 + 0x28) != iVar3)) {
        if (*(int *)(iVar1 + 0x24) == iVar3) goto LAB_0801cf06;
        uVar7 = FUN_08018960(iVar1 + 0xcc,local_4c);
        if (uVar7 == 0) goto LAB_0801ce50;
        iVar3 = uVar7 - (iVar1 + 0xcc);
        uVar7 = iVar3 >> 2;
        if (0x3c < iVar3) {
          uVar7 = uVar7 - 6;
        }
        uVar10 = uVar6;
        if (uVar2 <= 0xffffffff / uVar14) {
          uVar10 = uVar2 * uVar14;
          uVar2 = uVar7 + uVar10;
          if (CARRY4(uVar7,uVar10)) {
            uVar9 = uVar9 | 1;
          }
          uVar11 = uVar11 + 1;
          uVar10 = uVar9;
        }
      }
      else {
        if (uVar11 == 0) goto LAB_0801ce50;
        FUN_0800ac3e(local_2c,uVar11 & 0xff);
        uVar11 = 0;
        uVar10 = uVar9;
      }
      FUN_080187b2(uVar12);
      local_34 = 0xffffffff;
      local_38 = uVar12;
      iVar3 = FUN_0800e0fc(&local_38,&param_5);
      uVar9 = uVar10;
      if (iVar3 == 0) break;
      iVar3 = FUN_0800e0b8(&local_38);
      local_54 = local_34;
      uVar12 = local_38;
    }
    local_54 = local_34;
    uVar7 = 0;
    uVar12 = local_38;
    uVar13 = uVar6;
  }
  else {
    uVar2 = 0;
    uVar9 = 0;
LAB_0801cf06:
    uVar7 = 0;
  }
LAB_0801ce50:
  iVar3 = FUN_08018910(local_2c[0]);
  if (iVar3 != 0) {
    FUN_0800ac3e(local_2c,uVar11 & 0xff);
    iVar3 = FUN_0801fbd4(*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),local_2c);
    if (iVar3 == 0) {
      *param_8 = 4;
    }
  }
  uVar5 = local_2c[0];
  if ((((uVar11 == 0) && (uVar8 == 0)) && (iVar3 = FUN_08018910(local_2c[0]), iVar3 == 0)) ||
     (uVar7 != 0)) {
    uVar9 = 0;
  }
  else {
    if (uVar9 == 0) {
      if (bVar15) {
        uVar2 = -uVar2;
      }
      *param_9 = uVar2;
      goto LAB_0801cf24;
    }
    uVar9 = 0xffffffff;
  }
  *param_9 = uVar9;
  *param_8 = 4;
LAB_0801cf24:
  if (uVar13 != 0) {
    *param_8 = *param_8 | 2;
  }
  *param_1 = uVar12;
  param_1[1] = local_54;
  FUN_08018950(uVar5);
  return param_1;
}

