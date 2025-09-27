
undefined4 *
FUN_080162c8(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,undefined4 param_9)

{
  int *piVar1;
  uint *puVar2;
  char cVar3;
  byte bVar4;
  int iVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  int iVar12;
  undefined8 uVar13;
  uint local_68;
  uint local_64;
  uint local_60;
  uint local_5c;
  uint local_58;
  undefined4 local_40;
  undefined4 local_3c;
  char *local_34;
  char *local_30;
  undefined4 local_2c;
  
  puVar2 = param_8;
  iVar8 = param_7 + 0x6c;
  local_40 = param_3;
  local_3c = param_4;
  iVar5 = FUN_0801126c(iVar8);
  iVar8 = FUN_080119dc(iVar8);
  local_30 = DAT_0801657c;
  if (*(int *)(iVar8 + 0x20) == 0) {
    local_5c = 0;
  }
  else {
    local_5c = *(uint *)(iVar8 + 0x28);
    if (local_5c != 0) {
      local_5c = 1;
    }
  }
  local_34 = DAT_0801657c;
  if (*(char *)(iVar8 + 0x10) != '\0') {
    FUN_0800aa82(&local_34,0x20);
  }
  iVar10 = 0;
  FUN_0800aa82(&local_30,0x20);
  local_64 = 0;
  local_60 = 0;
  local_2c = *(undefined4 *)(iVar8 + 0x34);
  local_68 = 0;
  uVar11 = 0;
  local_58 = 0;
LAB_08016338:
  do {
    piVar1 = DAT_08016580;
    switch(*(undefined1 *)((int)&local_2c + iVar10)) {
    case 0:
      uVar9 = 1;
      goto LAB_080165d2;
    case 1:
      local_40 = param_3;
      local_3c = param_4;
      uVar7 = FUN_08012ee0(&local_40,&param_5);
      uVar9 = uVar7;
      param_3 = local_40;
      param_4 = local_3c;
      if (uVar7 != 0) {
        bVar4 = FUN_08012e9c(&local_40);
        param_3 = local_40;
        bVar4 = *(byte *)(*(int *)(iVar5 + 0x18) + (uint)bVar4);
        uVar9 = bVar4 & 8;
        param_4 = local_3c;
        if ((bVar4 & 8) != 0) {
          FUN_08010bc6(local_40);
          uVar9 = uVar7;
          param_4 = 0xffffffff;
        }
      }
LAB_080165d2:
      if (iVar10 == 3) goto LAB_08016426;
      while ((local_40 = param_3, local_3c = param_4, iVar6 = FUN_08012ee0(&local_40,&param_5),
             iVar6 != 0 &&
             (bVar4 = FUN_08012e9c(&local_40), param_3 = local_40,
             (int)((uint)*(byte *)(*(int *)(iVar5 + 0x18) + (uint)bVar4) << 0x1c) < 0))) {
        FUN_08010bc6(local_40);
        param_4 = 0xffffffff;
      }
      iVar10 = iVar10 + 1;
      param_3 = local_40;
      param_4 = local_3c;
      goto LAB_080165ee;
    case 2:
      if (((*(int *)(param_7 + 0xc) << 0x16 < 0) || (1 < local_64)) || (iVar10 == 0)) {
LAB_080163cc:
        iVar6 = *(int *)(iVar8 + 0x18);
        iVar12 = 0;
        while (local_40 = param_3, local_3c = param_4, uVar9 = FUN_08012ee0(&local_40,&param_5),
              param_3 = local_40, param_4 = local_3c, uVar9 != 0) {
          if (iVar12 == iVar6) goto LAB_0801641e;
          cVar3 = FUN_08012e9c(&local_40);
          param_3 = local_40;
          if (*(char *)(*(int *)(iVar8 + 0x14) + iVar12) != cVar3) goto LAB_08016408;
          FUN_08010bc6(local_40);
          iVar12 = iVar12 + 1;
          param_4 = 0xffffffff;
        }
        if (iVar12 == iVar6) goto switchD_08016342_default;
LAB_08016408:
        param_3 = local_40;
        param_4 = local_3c;
        if (iVar12 == 0) {
          uVar9 = ((uint)*(byte *)(param_7 + 0xd) << 0x1e) >> 0x1f ^ 1;
        }
        else {
          uVar9 = 0;
        }
        break;
      }
      if (iVar10 == 1) {
        if (((local_5c != 0) || ((char)local_2c == '\x03')) || (local_2c._2_1_ == '\x01'))
        goto LAB_080163cc;
        iVar10 = 2;
      }
      else {
        if (iVar10 != 2) {
          uVar9 = 1;
          goto LAB_08016426;
        }
        if (local_2c._3_1_ == '\x04') goto LAB_080163cc;
        if (local_5c != 0) {
          if (local_2c._3_1_ == '\x03') goto LAB_080163cc;
          iVar10 = 3;
          uVar9 = local_5c;
          goto LAB_080165ee;
        }
        iVar10 = 3;
      }
      goto LAB_08016338;
    case 3:
      if (((*(int *)(iVar8 + 0x20) == 0) ||
          (local_40 = param_3, local_3c = param_4, uVar9 = FUN_08012ee0(&local_40,&param_5),
          param_3 = local_40, param_4 = local_3c, uVar9 == 0)) ||
         (cVar3 = FUN_08012e9c(&local_40), param_3 = local_40, param_4 = local_3c,
         **(char **)(iVar8 + 0x1c) != cVar3)) {
        if (((*(int *)(iVar8 + 0x28) == 0) ||
            (local_40 = param_3, local_3c = param_4, uVar9 = FUN_08012ee0(&local_40,&param_5),
            param_3 = local_40, param_4 = local_3c, uVar9 == 0)) ||
           (cVar3 = FUN_08012e9c(&local_40), param_3 = local_40, param_4 = local_3c,
           **(char **)(iVar8 + 0x24) != cVar3)) {
          if ((*(int *)(iVar8 + 0x20) == 0) || (*(int *)(iVar8 + 0x28) != 0)) {
            uVar9 = local_5c ^ 1;
          }
          else {
            uVar9 = 1;
            local_58 = 1;
          }
          break;
        }
        local_64 = *(uint *)(iVar8 + 0x28);
        FUN_08010bc6(local_40);
        local_58 = uVar9;
      }
      else {
        local_64 = *(uint *)(iVar8 + 0x20);
        FUN_08010bc6(local_40);
      }
      param_4 = 0xffffffff;
      break;
    case 4:
      while (local_40 = param_3, local_3c = param_4, uVar9 = FUN_08012ee0(&local_40,&param_5),
            uVar9 != 0) {
        cVar3 = FUN_08012e9c(&local_40);
        iVar6 = FUN_08005e00(iVar8 + 0x39,cVar3,10);
        param_3 = local_40;
        if (iVar6 == 0) {
          if ((*(char *)(iVar8 + 0x11) == cVar3) && (local_68 == 0)) {
            if (*(int *)(iVar8 + 0x2c) < 1) goto LAB_08016372;
            local_60 = uVar11;
            uVar11 = 0;
            local_68 = uVar9;
          }
          else {
            if ((*(byte *)(iVar8 + 0x10) == 0) ||
               ((uVar9 = (uint)*(byte *)(iVar8 + 0x10), *(char *)(iVar8 + 0x12) != cVar3 ||
                (uVar9 = local_68, local_68 != 0)))) goto LAB_08016372;
            if (uVar11 == 0) {
              uVar9 = 0;
              goto LAB_08016372;
            }
            FUN_0800ac3e(&local_34,uVar11 & 0xff);
            uVar11 = 0;
          }
        }
        else {
          FUN_0800ac3e(&local_30,*(undefined1 *)(*piVar1 + (iVar6 - (iVar8 + 0x38))));
          uVar11 = uVar11 + 1;
        }
        FUN_08010bc6(param_3);
        param_4 = 0xffffffff;
      }
      uVar9 = 1;
LAB_08016372:
      param_4 = local_3c;
      param_3 = local_40;
      iVar6 = FUN_08010c1a(local_30);
      if (iVar6 == 0) {
        uVar9 = 0;
      }
      else {
        uVar9 = uVar9 & 1;
      }
      break;
    default:
switchD_08016342_default:
      uVar9 = 1;
    }
LAB_0801641e:
    iVar10 = iVar10 + 1;
    if (iVar10 == 4) {
LAB_08016426:
      if (local_64 < 2) {
        if (uVar9 != 0) goto LAB_0801666a;
      }
      else if (uVar9 != 0) {
        if (local_58 == 0) {
          iVar5 = *(int *)(iVar8 + 0x1c);
        }
        else {
          iVar5 = *(int *)(iVar8 + 0x24);
        }
        uVar9 = 1;
        break;
      }
      goto LAB_080165f4;
    }
LAB_080165ee:
    if (uVar9 == 0) goto LAB_080165f4;
  } while( true );
LAB_08016440:
  local_40 = param_3;
  local_3c = param_4;
  iVar10 = FUN_08012ee0(&local_40,&param_5);
  param_3 = local_40;
  param_4 = local_3c;
  if (iVar10 == 0) goto LAB_08016666;
  if (uVar9 == local_64) goto LAB_0801666a;
  cVar3 = FUN_08012e9c(&local_40);
  param_3 = local_40;
  param_4 = local_3c;
  if (*(char *)(iVar5 + uVar9) != cVar3) goto LAB_080165f4;
  FUN_08010bc6(local_40);
  uVar9 = uVar9 + 1;
  param_4 = 0xffffffff;
  goto LAB_08016440;
LAB_08016666:
  if (uVar9 == local_64) {
LAB_0801666a:
    uVar9 = FUN_08010c1a(local_30);
    if (1 < uVar9) {
      uVar13 = FUN_0800a726(&local_30,0x30,0);
      iVar5 = (int)uVar13;
      if (iVar5 != 0) {
        if (iVar5 == -1) {
          iVar5 = FUN_08010c1a(local_30,(int)((ulonglong)uVar13 >> 0x20),0xffffffff);
          iVar5 = iVar5 + -1;
        }
        FUN_08010c40(&local_30,0,iVar5);
      }
    }
    if ((local_58 != 0) && (FUN_0800a904(&local_30), *local_30 != '0')) {
      FUN_0800a904(&local_30);
      FUN_0800a984(&local_30,local_30,0x2d);
    }
    iVar5 = FUN_08010c1a(local_34);
    if (iVar5 != 0) {
      if (local_68 == 0) {
        local_60 = uVar11;
      }
      FUN_0800ac3e(&local_34,local_60 & 0xff);
      iVar5 = FUN_0801fbd4(*(undefined4 *)(iVar8 + 8),*(undefined4 *)(iVar8 + 0xc),&local_34);
      if (iVar5 == 0) {
        *puVar2 = *puVar2 | 4;
      }
    }
    if ((local_68 == 0) || (*(uint *)(iVar8 + 0x2c) == uVar11)) {
      FUN_0800a6fc(param_9,&local_30);
      goto LAB_08016702;
    }
  }
LAB_080165f4:
  *puVar2 = *puVar2 | 4;
LAB_08016702:
  local_40 = param_3;
  local_3c = param_4;
  iVar5 = FUN_08012eba(&local_40,&param_5);
  if (iVar5 != 0) {
    *puVar2 = *puVar2 | 2;
  }
  *param_1 = local_40;
  param_1[1] = local_3c;
  FUN_08010c74(local_30);
  FUN_08010c74(local_34);
  return param_1;
}

