
undefined4 *
FUN_08014014(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,undefined4 *param_8,undefined4 param_9
            )

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  uint uVar7;
  uint uVar8;
  undefined4 uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint local_48;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c [2];
  
  local_38 = param_3;
  local_34 = param_4;
  iVar2 = FUN_0801139c(param_7 + 0x6c);
  uVar3 = FUN_08012eba(&local_38,&param_5);
  if (uVar3 == 0) {
    bVar1 = FUN_08012e9c(&local_38);
    uVar9 = local_38;
    uVar7 = (uint)bVar1;
    if ((((*(byte *)(iVar2 + 0x4b) == uVar7) || (*(byte *)(iVar2 + 0x4a) == uVar7)) &&
        ((*(char *)(iVar2 + 0x10) == '\0' || (*(byte *)(iVar2 + 0x25) != uVar7)))) &&
       (*(byte *)(iVar2 + 0x24) != uVar7)) {
      if (*(byte *)(iVar2 + 0x4b) == uVar7) {
        uVar6 = 0x2b;
      }
      else {
        uVar6 = 0x2d;
      }
      FUN_0800ac3e(param_9,uVar6);
      FUN_08010bc6(uVar9);
      local_34 = 0xffffffff;
      iVar4 = FUN_08012ee0(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar3 = 1;
        uVar10 = 0;
        uVar12 = 0;
        goto LAB_080140a2;
      }
      bVar1 = FUN_08012e9c(&local_38);
      uVar7 = (uint)bVar1;
    }
    uVar10 = 0;
    uVar12 = 0;
    while( true ) {
      uVar9 = local_38;
      if ((((*(char *)(iVar2 + 0x10) != '\0') && (*(byte *)(iVar2 + 0x25) == uVar7)) ||
          (*(byte *)(iVar2 + 0x24) == uVar7)) || (*(byte *)(iVar2 + 0x4e) != uVar7))
      goto LAB_080140a2;
      if (uVar10 == 0) {
        FUN_0800ac3e(param_9,0x30);
      }
      FUN_08010bc6(uVar9);
      local_34 = 0xffffffff;
      local_38 = uVar9;
      uVar10 = FUN_08012ee0(&local_38,&param_5);
      uVar12 = uVar12 + 1;
      if (uVar10 == 0) break;
      bVar1 = FUN_08012e9c(&local_38);
      uVar7 = (uint)bVar1;
    }
    uVar3 = 1;
    uVar10 = 1;
  }
  else {
    uVar7 = 0;
    uVar12 = 0;
    uVar10 = 0;
  }
LAB_080140a2:
  uVar6 = local_34;
  uVar9 = local_38;
  local_2c[0] = DAT_0801432c;
  if (*(char *)(iVar2 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar11 = (uint)*(byte *)(iVar2 + 100);
  if (uVar11 == 0) {
    uVar8 = uVar11;
    local_48 = uVar11;
    uVar11 = uVar3;
    if (uVar3 == 0) {
LAB_080141b6:
      local_48 = uVar11;
      if (uVar7 - 0x30 < 10) {
        FUN_0800ac3e(param_9,uVar7);
        uVar10 = 1;
        goto LAB_080141ca;
      }
      if (((*(byte *)(iVar2 + 0x24) == uVar7) && (local_48 == 0)) && (uVar3 == 0)) {
        FUN_0800ac3e(param_9,0x2e);
        local_48 = 1;
        goto LAB_080141ca;
      }
      uVar8 = uVar3;
      if (((*(byte *)(iVar2 + 0x5c) == uVar7) || (*(byte *)(iVar2 + 0x62) == uVar7)) &&
         ((uVar3 == 0 && (uVar10 != 0)))) {
        FUN_0800ac3e(param_9,0x65);
        FUN_08010bc6(uVar9);
        local_34 = 0xffffffff;
        local_38 = uVar9;
        uVar3 = FUN_08012ee0(&local_38,&param_5);
        uVar8 = uVar10;
        uVar9 = local_38;
        uVar6 = local_34;
        if (uVar3 != 0) {
          bVar1 = FUN_08012e9c(&local_38);
          uVar9 = local_38;
          uVar7 = (uint)bVar1;
          uVar10 = uVar3;
          if (*(byte *)(iVar2 + 0x4b) != uVar7) goto code_r0x0801425c;
          uVar6 = 0x2b;
          goto LAB_08014270;
        }
      }
    }
    goto LAB_08014292;
  }
  if (uVar3 != 0) {
    uVar8 = 0;
    local_48 = 0;
LAB_08014292:
    iVar4 = FUN_08010c1a(local_2c[0]);
    if (iVar4 != 0) {
      if ((local_48 == 0) && (uVar8 == 0)) {
        FUN_0800ac3e(local_2c,uVar12 & 0xff);
      }
      iVar2 = FUN_0801fbd4(*(undefined4 *)(iVar2 + 8),*(undefined4 *)(iVar2 + 0xc),local_2c);
      if (iVar2 == 0) {
        *param_8 = 4;
      }
    }
    *param_1 = uVar9;
    param_1[1] = uVar6;
    FUN_08010c74(local_2c[0]);
    return param_1;
  }
  local_48 = uVar3;
LAB_080140ce:
  uVar5 = uVar3;
  uVar8 = uVar5;
  if ((*(char *)(iVar2 + 0x10) == '\0') || (*(byte *)(iVar2 + 0x25) != uVar7)) {
    if (*(byte *)(iVar2 + 0x24) == uVar7) {
      iVar4 = FUN_08010c1a(local_2c[0]);
      if ((local_48 == 0) && (uVar5 == 0)) {
        if (iVar4 != 0) {
          FUN_0800ac3e(local_2c,uVar12 & 0xff);
        }
        FUN_0800ac3e(param_9,0x2e);
        local_48 = uVar11;
        goto LAB_08014102;
      }
    }
    else {
      iVar4 = FUN_08005e00(iVar2 + 0x4e,uVar7,10);
      if (iVar4 != 0) {
        FUN_0800ac3e(param_9,(iVar4 - (iVar2 + 0x4e)) + 0x30U & 0xff);
        uVar12 = uVar12 + 1;
        uVar10 = uVar11;
        goto LAB_08014102;
      }
      if ((((*(byte *)(iVar2 + 0x5c) == uVar7) || (*(byte *)(iVar2 + 0x62) == uVar7)) &&
          (iVar4 = FUN_08010c1a(local_2c[0]), uVar5 == 0)) && (uVar10 != 0)) {
        if ((iVar4 != 0) && (local_48 == 0)) {
          FUN_0800ac3e(local_2c,uVar12 & 0xff);
        }
        FUN_0800ac3e(param_9,0x65);
        FUN_08010bc6(uVar9);
        local_34 = 0xffffffff;
        local_38 = uVar9;
        uVar5 = FUN_08012ee0(&local_38,&param_5);
        uVar8 = uVar10;
        uVar9 = local_38;
        uVar6 = local_34;
        if (uVar5 != 0) goto code_r0x08014384;
      }
    }
  }
  else if ((local_48 == 0) && (uVar5 == 0)) {
    if (uVar12 != 0) {
      FUN_0800ac3e(local_2c,uVar12 & 0xff);
      uVar12 = 0;
      goto LAB_08014102;
    }
    FUN_0800a818(param_9);
  }
  goto LAB_08014292;
code_r0x0801425c:
  uVar6 = local_34;
  uVar11 = local_48;
  if (*(byte *)(iVar2 + 0x4a) == uVar7) {
    uVar6 = 0x2d;
LAB_08014270:
    FUN_0800ac3e(param_9,uVar6);
LAB_080141ca:
    FUN_08010bc6(uVar9);
    local_34 = 0xffffffff;
    local_38 = uVar9;
    iVar4 = FUN_08012ee0(&local_38,&param_5);
    uVar8 = uVar3;
    uVar9 = local_38;
    uVar6 = local_34;
    if (iVar4 == 0) goto LAB_08014292;
    bVar1 = FUN_08012e9c(&local_38);
    uVar7 = (uint)bVar1;
    uVar9 = local_38;
    uVar6 = local_34;
    uVar11 = local_48;
  }
  goto LAB_080141b6;
code_r0x08014384:
  bVar1 = FUN_08012e9c(&local_38);
  uVar9 = local_38;
  uVar7 = (uint)bVar1;
  uVar6 = local_34;
  if ((((*(byte *)(iVar2 + 0x4b) == uVar7) ||
       (uVar3 = uVar5, uVar10 = uVar5, *(byte *)(iVar2 + 0x4a) == uVar7)) &&
      ((uVar3 = (uint)*(byte *)(iVar2 + 0x10), uVar3 == 0 ||
       (uVar10 = uVar3, *(byte *)(iVar2 + 0x25) != uVar7)))) &&
     (uVar3 = uVar5, uVar10 = uVar5, *(byte *)(iVar2 + 0x24) != uVar7)) {
    if (*(byte *)(iVar2 + 0x4b) == uVar7) {
      uVar6 = 0x2b;
    }
    else {
      uVar6 = 0x2d;
    }
    FUN_0800ac3e(param_9,uVar6);
LAB_08014102:
    FUN_08010bc6(uVar9);
    local_34 = 0xffffffff;
    local_38 = uVar9;
    iVar4 = FUN_08012ee0(&local_38,&param_5);
    uVar8 = uVar5;
    uVar9 = local_38;
    uVar6 = local_34;
    if (iVar4 == 0) goto LAB_08014292;
    bVar1 = FUN_08012e9c(&local_38);
    uVar7 = (uint)bVar1;
    uVar3 = uVar5;
    uVar9 = local_38;
    uVar6 = local_34;
  }
  goto LAB_080140ce;
}

