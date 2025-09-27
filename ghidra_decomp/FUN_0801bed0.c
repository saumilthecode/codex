
undefined4 *
FUN_0801bed0(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
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
  undefined4 local_58;
  uint local_50;
  uint local_48;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c [2];
  
  iVar3 = param_7;
  local_38 = param_3;
  local_34 = param_4;
  iVar1 = FUN_08018fd4(param_7 + 0x6c);
  uVar10 = *(uint *)(iVar3 + 0xc) & 0x4a;
  if (uVar10 == 0x40) {
    uVar14 = 8;
  }
  else if (uVar10 == 8) {
    uVar14 = 0x10;
  }
  else {
    uVar14 = 10;
  }
  uVar2 = FUN_0800e0d6(&local_38,&param_5);
  if (uVar2 == 0) {
    iVar3 = FUN_0800e0b8(&local_38);
    if ((*(int *)(iVar1 + 0xbc) == iVar3) || (*(int *)(iVar1 + 0xc0) == iVar3)) {
      local_50 = (uint)(*(int *)(iVar1 + 0xbc) == iVar3);
      if (((*(char *)(iVar1 + 0x10) == '\0') || (*(int *)(iVar1 + 0x28) != iVar3)) &&
         (*(int *)(iVar1 + 0x24) != iVar3)) {
        FUN_080187b2(local_38);
        local_34 = 0xffffffff;
        iVar4 = FUN_0800e0fc(&local_38,&param_5);
        if (iVar4 == 0) {
          uVar9 = 0;
          uVar11 = 0;
          uVar13 = 1;
          goto LAB_0801bf74;
        }
        iVar3 = FUN_0800e0b8(&local_38);
      }
    }
    else {
      local_50 = 0;
    }
    uVar9 = 0;
    uVar11 = 0;
    do {
      uVar12 = local_38;
      if (((*(char *)(iVar1 + 0x10) != '\0') && (uVar13 = uVar2, *(int *)(iVar1 + 0x28) == iVar3))
         || (uVar13 = uVar2, *(int *)(iVar1 + 0x24) == iVar3)) break;
      if (*(int *)(iVar1 + 0xcc) == iVar3) {
        if (uVar9 == 0) {
          if (uVar10 != 0) {
            if (uVar14 != 8) goto LAB_0801c05a;
            uVar11 = 0;
LAB_0801c05c:
            uVar9 = 1;
            goto LAB_0801c080;
          }
          uVar9 = 1;
        }
        else {
          if (uVar14 != 10) goto LAB_0801c064;
          if (uVar10 != 0) {
LAB_0801c05a:
            uVar11 = uVar11 + 1;
            goto LAB_0801c05c;
          }
        }
        uVar14 = 8;
        uVar11 = uVar10;
      }
      else {
        uVar13 = uVar9;
        if (uVar9 == 0) break;
LAB_0801c064:
        if ((*(int *)(iVar1 + 0xc4) != iVar3) && (*(int *)(iVar1 + 200) != iVar3)) {
          uVar9 = 1;
          uVar13 = uVar2;
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
            uVar13 = uVar2;
            local_48 = uVar14;
            goto LAB_0801bf80;
          }
          uVar9 = 0;
          uVar11 = 0;
        }
      }
LAB_0801c080:
      FUN_080187b2(local_38);
      local_34 = 0xffffffff;
      local_38 = uVar12;
      iVar4 = FUN_0800e0fc(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar13 = 1;
        break;
      }
      iVar3 = FUN_0800e0b8(&local_38);
      uVar13 = uVar9;
    } while (uVar9 != 0);
  }
  else {
    iVar3 = 0;
    local_50 = 0;
    uVar11 = 0;
    uVar9 = 0;
    uVar13 = uVar2;
  }
LAB_0801bf74:
  local_48 = uVar14;
  if (uVar14 == 0x10) {
    local_48 = 0x16;
  }
LAB_0801bf80:
  local_58 = local_34;
  uVar12 = local_38;
  local_2c[0] = DAT_0801c218;
  if (*(char *)(iVar1 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar6 = local_50 + 0x7fffffff;
  uVar7 = (uint)*(byte *)(iVar1 + 0x124);
  uVar2 = uVar13;
  uVar10 = uVar13;
  if (uVar7 == 0) {
    if (uVar13 == 0) {
      while (iVar3 = FUN_0801882c(local_48,iVar3), iVar3 != -1) {
        if (uVar6 / uVar14 < uVar2) {
          uVar10 = 1;
        }
        else {
          if (uVar6 - iVar3 < uVar2 * uVar14) {
            uVar10 = uVar10 | 1;
          }
          uVar11 = uVar11 + 1;
          uVar2 = uVar2 * uVar14 + iVar3;
        }
        FUN_080187b2(uVar12);
        local_34 = 0xffffffff;
        local_38 = uVar12;
        iVar3 = FUN_0800e0fc(&local_38,&param_5);
        if (iVar3 == 0) {
          uVar13 = 1;
          local_58 = local_34;
          uVar8 = 0;
          uVar12 = local_38;
          goto LAB_0801c14e;
        }
        iVar3 = FUN_0800e0b8(&local_38);
        local_58 = local_34;
        uVar12 = local_38;
      }
      goto LAB_0801c208;
    }
    uVar8 = 0;
    uVar2 = 0;
    uVar10 = uVar7;
  }
  else if (uVar13 == 0) {
    while( true ) {
      uVar8 = (uint)*(byte *)(iVar1 + 0x10);
      if ((uVar8 == 0) || (*(int *)(iVar1 + 0x28) != iVar3)) {
        if (*(int *)(iVar1 + 0x24) == iVar3) goto LAB_0801c208;
        uVar8 = FUN_08018960(iVar1 + 0xcc,local_48);
        if (uVar8 == 0) goto LAB_0801c14e;
        iVar4 = uVar8 - (iVar1 + 0xcc);
        iVar3 = iVar4 >> 2;
        if (0x3c < iVar4) {
          iVar3 = iVar3 + -6;
        }
        uVar8 = uVar7;
        if (uVar2 <= uVar6 / uVar14) {
          if (uVar6 - iVar3 < uVar2 * uVar14) {
            uVar10 = uVar10 | 1;
          }
          uVar11 = uVar11 + 1;
          uVar2 = uVar2 * uVar14 + iVar3;
          uVar8 = uVar10;
        }
      }
      else {
        if (uVar11 == 0) goto LAB_0801c14e;
        FUN_0800ac3e(local_2c,uVar11 & 0xff);
        uVar11 = 0;
        uVar8 = uVar10;
      }
      FUN_080187b2(uVar12);
      local_34 = 0xffffffff;
      local_38 = uVar12;
      iVar3 = FUN_0800e0fc(&local_38,&param_5);
      uVar10 = uVar8;
      if (iVar3 == 0) break;
      iVar3 = FUN_0800e0b8(&local_38);
      local_58 = local_34;
      uVar12 = local_38;
    }
    local_58 = local_34;
    uVar8 = 0;
    uVar12 = local_38;
    uVar13 = uVar7;
  }
  else {
    uVar2 = 0;
    uVar10 = 0;
LAB_0801c208:
    uVar8 = 0;
  }
LAB_0801c14e:
  iVar3 = FUN_08018910(local_2c[0]);
  if (iVar3 != 0) {
    FUN_0800ac3e(local_2c,uVar11 & 0xff);
    iVar3 = FUN_0801fbd4(*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),local_2c);
    if (iVar3 == 0) {
      *param_8 = 4;
    }
  }
  uVar5 = local_2c[0];
  if ((((uVar11 == 0) && (uVar9 == 0)) && (iVar3 = FUN_08018910(local_2c[0]), iVar3 == 0)) ||
     (uVar8 != 0)) {
    uVar10 = 0;
  }
  else {
    if (uVar10 == 0) {
      if (local_50 != 0) {
        uVar2 = -uVar2;
      }
      *param_9 = uVar2;
      goto LAB_0801c228;
    }
    uVar10 = ~(-local_50 ^ 0x80000000);
  }
  *param_9 = uVar10;
  *param_8 = 4;
LAB_0801c228:
  if (uVar13 != 0) {
    *param_8 = *param_8 | 2;
  }
  *param_1 = uVar12;
  param_1[1] = local_58;
  FUN_08018950(uVar5);
  return param_1;
}

