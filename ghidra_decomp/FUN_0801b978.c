
undefined4 *
FUN_0801b978(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,undefined4 *param_8,undefined4 param_9
            )

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  uint uVar7;
  undefined4 uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint local_48;
  undefined4 local_38;
  undefined4 local_34;
  undefined4 local_2c [2];
  
  local_38 = param_3;
  local_34 = param_4;
  iVar1 = FUN_08018fd4(param_7 + 0x6c);
  uVar2 = FUN_0800e0d6(&local_38,&param_5);
  if (uVar2 == 0) {
    uVar3 = FUN_0800e0b8(&local_38);
    uVar8 = local_38;
    if ((((*(uint *)(iVar1 + 0xc0) == uVar3) || (*(uint *)(iVar1 + 0xbc) == uVar3)) &&
        ((*(char *)(iVar1 + 0x10) == '\0' || (*(uint *)(iVar1 + 0x28) != uVar3)))) &&
       (*(uint *)(iVar1 + 0x24) != uVar3)) {
      if (*(uint *)(iVar1 + 0xc0) == uVar3) {
        uVar6 = 0x2b;
      }
      else {
        uVar6 = 0x2d;
      }
      FUN_0800ac3e(param_9,uVar6);
      FUN_080187b2(uVar8);
      local_34 = 0xffffffff;
      iVar4 = FUN_0800e0fc(&local_38,&param_5);
      if (iVar4 == 0) {
        uVar2 = 1;
        uVar9 = 0;
        uVar11 = 0;
        goto LAB_0801ba02;
      }
      uVar3 = FUN_0800e0b8(&local_38);
    }
    uVar9 = 0;
    uVar11 = 0;
    while( true ) {
      uVar8 = local_38;
      if ((((*(char *)(iVar1 + 0x10) != '\0') && (*(uint *)(iVar1 + 0x28) == uVar3)) ||
          (*(uint *)(iVar1 + 0x24) == uVar3)) || (*(uint *)(iVar1 + 0xcc) != uVar3))
      goto LAB_0801ba02;
      if (uVar9 == 0) {
        FUN_0800ac3e(param_9,0x30);
      }
      FUN_080187b2(uVar8);
      local_34 = 0xffffffff;
      local_38 = uVar8;
      uVar9 = FUN_0800e0fc(&local_38,&param_5);
      uVar11 = uVar11 + 1;
      if (uVar9 == 0) break;
      uVar3 = FUN_0800e0b8(&local_38);
    }
    uVar2 = 1;
    uVar9 = 1;
  }
  else {
    uVar3 = 0;
    uVar11 = 0;
    uVar9 = 0;
  }
LAB_0801ba02:
  uVar6 = local_34;
  uVar8 = local_38;
  local_2c[0] = DAT_0801bc80;
  if (*(char *)(iVar1 + 0x10) != '\0') {
    FUN_0800aa82(local_2c,0x20);
  }
  uVar10 = (uint)*(byte *)(iVar1 + 0x124);
  if (uVar10 == 0) {
    uVar7 = uVar10;
    local_48 = uVar10;
    uVar10 = uVar2;
    if (uVar2 == 0) {
LAB_0801bb10:
      local_48 = uVar10;
      if (uVar3 - 0x30 < 10) {
        FUN_0800ac3e(param_9,uVar3 & 0xff);
        uVar9 = 1;
        goto LAB_0801bb24;
      }
      if (((*(uint *)(iVar1 + 0x24) == uVar3) && (local_48 == 0)) && (uVar2 == 0)) {
        FUN_0800ac3e(param_9,0x2e);
        local_48 = 1;
        goto LAB_0801bb24;
      }
      uVar7 = uVar2;
      if (((*(uint *)(iVar1 + 0x104) == uVar3) || (*(uint *)(iVar1 + 0x11c) == uVar3)) &&
         ((uVar2 == 0 && (uVar9 != 0)))) {
        FUN_0800ac3e(param_9,0x65);
        FUN_080187b2(uVar8);
        local_34 = 0xffffffff;
        local_38 = uVar8;
        uVar2 = FUN_0800e0fc(&local_38,&param_5);
        uVar7 = uVar9;
        uVar8 = local_38;
        uVar6 = local_34;
        if (uVar2 != 0) {
          uVar3 = FUN_0800e0b8(&local_38);
          uVar8 = local_38;
          uVar9 = uVar2;
          if (*(uint *)(iVar1 + 0xc0) != uVar3) goto code_r0x0801bbb2;
          uVar6 = 0x2b;
          goto LAB_0801bbc6;
        }
      }
    }
    goto LAB_0801bbe8;
  }
  if (uVar2 != 0) {
    uVar7 = 0;
    local_48 = 0;
LAB_0801bbe8:
    iVar4 = FUN_08018910(local_2c[0]);
    if (iVar4 != 0) {
      if ((local_48 == 0) && (uVar7 == 0)) {
        FUN_0800ac3e(local_2c,uVar11 & 0xff);
      }
      iVar1 = FUN_0801fbd4(*(undefined4 *)(iVar1 + 8),*(undefined4 *)(iVar1 + 0xc),local_2c);
      if (iVar1 == 0) {
        *param_8 = 4;
      }
    }
    *param_1 = uVar8;
    param_1[1] = uVar6;
    FUN_08018950(local_2c[0]);
    return param_1;
  }
  local_48 = uVar2;
LAB_0801ba2e:
  uVar5 = uVar2;
  uVar7 = uVar5;
  if ((*(char *)(iVar1 + 0x10) == '\0') || (*(uint *)(iVar1 + 0x28) != uVar3)) {
    if (*(uint *)(iVar1 + 0x24) == uVar3) {
      iVar4 = FUN_08018910(local_2c[0]);
      if ((local_48 == 0) && (uVar5 == 0)) {
        if (iVar4 != 0) {
          FUN_0800ac3e(local_2c,uVar11 & 0xff);
        }
        FUN_0800ac3e(param_9,0x2e);
        local_48 = uVar10;
        goto LAB_0801ba60;
      }
    }
    else {
      iVar4 = FUN_080269a2(iVar1 + 0xcc,uVar3,10);
      if (iVar4 != 0) {
        FUN_0800ac3e(param_9,(iVar4 - (iVar1 + 0xcc) >> 2) + 0x30U & 0xff);
        uVar11 = uVar11 + 1;
        uVar9 = uVar10;
        goto LAB_0801ba60;
      }
      if ((((*(uint *)(iVar1 + 0x104) == uVar3) || (*(uint *)(iVar1 + 0x11c) == uVar3)) &&
          (iVar4 = FUN_08018910(local_2c[0]), uVar5 == 0)) && (uVar9 != 0)) {
        if ((iVar4 != 0) && (local_48 == 0)) {
          FUN_0800ac3e(local_2c,uVar11 & 0xff);
        }
        FUN_0800ac3e(param_9,0x65);
        FUN_080187b2(uVar8);
        local_34 = 0xffffffff;
        local_38 = uVar8;
        uVar5 = FUN_0800e0fc(&local_38,&param_5);
        uVar7 = uVar9;
        uVar8 = local_38;
        uVar6 = local_34;
        if (uVar5 != 0) goto code_r0x0801bcd8;
      }
    }
  }
  else if ((local_48 == 0) && (uVar5 == 0)) {
    if (uVar11 != 0) {
      FUN_0800ac3e(local_2c,uVar11 & 0xff);
      uVar11 = 0;
      goto LAB_0801ba60;
    }
    FUN_0800a818(param_9);
  }
  goto LAB_0801bbe8;
code_r0x0801bbb2:
  uVar6 = local_34;
  uVar10 = local_48;
  if (*(uint *)(iVar1 + 0xbc) == uVar3) {
    uVar6 = 0x2d;
LAB_0801bbc6:
    FUN_0800ac3e(param_9,uVar6);
LAB_0801bb24:
    FUN_080187b2(uVar8);
    local_34 = 0xffffffff;
    local_38 = uVar8;
    iVar4 = FUN_0800e0fc(&local_38,&param_5);
    uVar7 = uVar2;
    uVar8 = local_38;
    uVar6 = local_34;
    if (iVar4 == 0) goto LAB_0801bbe8;
    uVar3 = FUN_0800e0b8(&local_38);
    uVar8 = local_38;
    uVar6 = local_34;
    uVar10 = local_48;
  }
  goto LAB_0801bb10;
code_r0x0801bcd8:
  uVar3 = FUN_0800e0b8(&local_38);
  uVar8 = local_38;
  uVar6 = local_34;
  if ((((*(uint *)(iVar1 + 0xc0) == uVar3) ||
       (uVar2 = uVar5, uVar9 = uVar5, *(uint *)(iVar1 + 0xbc) == uVar3)) &&
      ((uVar2 = (uint)*(byte *)(iVar1 + 0x10), uVar2 == 0 ||
       (uVar9 = uVar2, *(uint *)(iVar1 + 0x28) != uVar3)))) &&
     (uVar2 = uVar5, uVar9 = uVar5, *(uint *)(iVar1 + 0x24) != uVar3)) {
    if (*(uint *)(iVar1 + 0xc0) == uVar3) {
      uVar6 = 0x2b;
    }
    else {
      uVar6 = 0x2d;
    }
    FUN_0800ac3e(param_9,uVar6);
LAB_0801ba60:
    FUN_080187b2(uVar8);
    local_34 = 0xffffffff;
    local_38 = uVar8;
    iVar4 = FUN_0800e0fc(&local_38,&param_5);
    uVar7 = uVar5;
    uVar8 = local_38;
    uVar6 = local_34;
    if (iVar4 == 0) goto LAB_0801bbe8;
    uVar3 = FUN_0800e0b8(&local_38);
    uVar2 = uVar5;
    uVar8 = local_38;
    uVar6 = local_34;
  }
  goto LAB_0801ba2e;
}

