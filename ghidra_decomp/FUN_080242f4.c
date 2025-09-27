
undefined4 *
FUN_080242f4(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
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
  uint local_90;
  uint local_8c;
  uint local_88;
  uint local_84;
  uint local_80;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_5c;
  undefined1 *local_58;
  int local_54;
  undefined1 local_50 [16];
  char *local_40;
  uint local_3c;
  char local_38 [20];
  
  puVar2 = param_8;
  iVar8 = param_7 + 0x6c;
  local_68 = param_3;
  local_64 = param_4;
  iVar5 = FUN_0801126c(iVar8);
  iVar8 = FUN_08021cf8(iVar8);
  if (*(int *)(iVar8 + 0x20) == 0) {
    local_84 = 0;
  }
  else {
    local_84 = *(uint *)(iVar8 + 0x28);
    if (local_84 != 0) {
      local_84 = 1;
    }
  }
  local_58 = local_50;
  local_54 = 0;
  local_50[0] = 0;
  if (*(char *)(iVar8 + 0x10) != '\0') {
    FUN_08017ea8(&local_58,0x20);
  }
  iVar10 = 0;
  local_40 = local_38;
  local_3c = 0;
  local_38[0] = '\0';
  FUN_08017ea8(&local_40,0x20);
  local_8c = 0;
  local_88 = 0;
  local_5c = *(undefined4 *)(iVar8 + 0x34);
  local_90 = 0;
  uVar11 = 0;
  local_80 = 0;
LAB_08024376:
  do {
    piVar1 = DAT_080245f0;
    switch(*(undefined1 *)((int)&local_5c + iVar10)) {
    case 0:
      uVar9 = 1;
      goto LAB_08024608;
    case 1:
      local_68 = param_3;
      local_64 = param_4;
      uVar7 = FUN_08012ee0(&local_68,&param_5);
      uVar9 = uVar7;
      param_3 = local_68;
      param_4 = local_64;
      if (uVar7 != 0) {
        bVar4 = FUN_08012e9c(&local_68);
        param_3 = local_68;
        bVar4 = *(byte *)(*(int *)(iVar5 + 0x18) + (uint)bVar4);
        uVar9 = bVar4 & 8;
        param_4 = local_64;
        if ((bVar4 & 8) != 0) {
          FUN_08021b24(local_68);
          uVar9 = uVar7;
          param_4 = 0xffffffff;
        }
      }
LAB_08024608:
      if (iVar10 == 3) goto LAB_08024460;
      while ((local_68 = param_3, local_64 = param_4, iVar6 = FUN_08012ee0(&local_68,&param_5),
             iVar6 != 0 &&
             (bVar4 = FUN_08012e9c(&local_68), param_3 = local_68,
             (int)((uint)*(byte *)(*(int *)(iVar5 + 0x18) + (uint)bVar4) << 0x1c) < 0))) {
        FUN_08021b24(local_68);
        param_4 = 0xffffffff;
      }
      iVar10 = iVar10 + 1;
      param_3 = local_68;
      param_4 = local_64;
      goto LAB_08024624;
    case 2:
      if (((*(int *)(param_7 + 0xc) << 0x16 < 0) || (1 < local_8c)) || (iVar10 == 0)) {
LAB_08024406:
        iVar6 = *(int *)(iVar8 + 0x18);
        iVar12 = 0;
        while (local_68 = param_3, local_64 = param_4, uVar9 = FUN_08012ee0(&local_68,&param_5),
              param_3 = local_68, param_4 = local_64, uVar9 != 0) {
          if (iVar12 == iVar6) goto LAB_08024458;
          cVar3 = FUN_08012e9c(&local_68);
          param_3 = local_68;
          if (*(char *)(*(int *)(iVar8 + 0x14) + iVar12) != cVar3) goto LAB_08024442;
          FUN_08021b24(local_68);
          iVar12 = iVar12 + 1;
          param_4 = 0xffffffff;
        }
        if (iVar12 == iVar6) goto switchD_08024380_default;
LAB_08024442:
        param_3 = local_68;
        param_4 = local_64;
        if (iVar12 == 0) {
          uVar9 = ((uint)*(byte *)(param_7 + 0xd) << 0x1e) >> 0x1f ^ 1;
        }
        else {
          uVar9 = 0;
        }
        break;
      }
      if (iVar10 == 1) {
        if (((local_84 != 0) || ((char)local_5c == '\x03')) || (local_5c._2_1_ == '\x01'))
        goto LAB_08024406;
        iVar10 = 2;
      }
      else {
        if (iVar10 != 2) {
          uVar9 = 1;
          goto LAB_08024460;
        }
        if (local_5c._3_1_ == '\x04') goto LAB_08024406;
        if (local_84 != 0) {
          if (local_5c._3_1_ == '\x03') goto LAB_08024406;
          iVar10 = 3;
          uVar9 = local_84;
          goto LAB_08024624;
        }
        iVar10 = 3;
      }
      goto LAB_08024376;
    case 3:
      if (((*(int *)(iVar8 + 0x20) == 0) ||
          (local_68 = param_3, local_64 = param_4, uVar9 = FUN_08012ee0(&local_68,&param_5),
          param_3 = local_68, param_4 = local_64, uVar9 == 0)) ||
         (cVar3 = FUN_08012e9c(&local_68), param_3 = local_68, param_4 = local_64,
         **(char **)(iVar8 + 0x1c) != cVar3)) {
        if (((*(int *)(iVar8 + 0x28) == 0) ||
            (local_68 = param_3, local_64 = param_4, uVar9 = FUN_08012ee0(&local_68,&param_5),
            param_3 = local_68, param_4 = local_64, uVar9 == 0)) ||
           (cVar3 = FUN_08012e9c(&local_68), param_3 = local_68, param_4 = local_64,
           **(char **)(iVar8 + 0x24) != cVar3)) {
          if ((*(int *)(iVar8 + 0x20) == 0) || (*(int *)(iVar8 + 0x28) != 0)) {
            uVar9 = local_84 ^ 1;
          }
          else {
            uVar9 = 1;
            local_80 = 1;
          }
          break;
        }
        local_8c = *(uint *)(iVar8 + 0x28);
        FUN_08021b24(local_68);
        local_80 = uVar9;
      }
      else {
        local_8c = *(uint *)(iVar8 + 0x20);
        FUN_08021b24(local_68);
      }
      param_4 = 0xffffffff;
      break;
    case 4:
      while (local_68 = param_3, local_64 = param_4, uVar9 = FUN_08012ee0(&local_68,&param_5),
            uVar9 != 0) {
        cVar3 = FUN_08012e9c(&local_68);
        iVar6 = FUN_08005e00(iVar8 + 0x39,cVar3,10);
        param_3 = local_68;
        if (iVar6 == 0) {
          if ((*(char *)(iVar8 + 0x11) == cVar3) && (local_90 == 0)) {
            if (*(int *)(iVar8 + 0x2c) < 1) goto LAB_080243b0;
            local_88 = uVar11;
            uVar11 = 0;
            local_90 = uVar9;
          }
          else {
            if ((*(byte *)(iVar8 + 0x10) == 0) ||
               ((uVar9 = (uint)*(byte *)(iVar8 + 0x10), *(char *)(iVar8 + 0x12) != cVar3 ||
                (uVar9 = local_90, local_90 != 0)))) goto LAB_080243b0;
            if (uVar11 == 0) {
              uVar9 = 0;
              goto LAB_080243b0;
            }
            FUN_08017ede(&local_58,uVar11 & 0xff);
            uVar11 = 0;
          }
        }
        else {
          FUN_08017ede(&local_40,*(undefined1 *)(*piVar1 + (iVar6 - (iVar8 + 0x38))));
          uVar11 = uVar11 + 1;
        }
        FUN_08021b24(param_3);
        param_4 = 0xffffffff;
      }
      uVar9 = 1;
LAB_080243b0:
      param_3 = local_68;
      param_4 = local_64;
      if (local_3c == 0) {
        uVar9 = 0;
      }
      else {
        uVar9 = uVar9 & 1;
      }
      break;
    default:
switchD_08024380_default:
      uVar9 = 1;
    }
LAB_08024458:
    iVar10 = iVar10 + 1;
    if (iVar10 == 4) {
LAB_08024460:
      if (local_8c < 2) {
        if (uVar9 != 0) goto LAB_080246a0;
      }
      else if (uVar9 != 0) {
        if (local_80 == 0) {
          iVar5 = *(int *)(iVar8 + 0x1c);
        }
        else {
          iVar5 = *(int *)(iVar8 + 0x24);
        }
        uVar9 = 1;
        break;
      }
      goto LAB_0802462a;
    }
LAB_08024624:
    if (uVar9 == 0) goto LAB_0802462a;
  } while( true );
LAB_0802447a:
  local_68 = param_3;
  local_64 = param_4;
  iVar10 = FUN_08012ee0(&local_68,&param_5);
  param_3 = local_68;
  param_4 = local_64;
  if (iVar10 == 0) goto LAB_0802469c;
  if (uVar9 == local_8c) goto LAB_080246a0;
  cVar3 = FUN_08012e9c(&local_68);
  param_3 = local_68;
  param_4 = local_64;
  if (*(char *)(iVar5 + uVar9) != cVar3) goto LAB_0802462a;
  FUN_08021b24(local_68);
  uVar9 = uVar9 + 1;
  param_4 = 0xffffffff;
  goto LAB_0802447a;
LAB_0802469c:
  if (uVar9 == local_8c) {
LAB_080246a0:
    if ((1 < local_3c) && (iVar5 = FUN_08018262(&local_40,0x30,0), iVar5 != 0)) {
      if (iVar5 == -1) {
        iVar5 = local_3c - 1;
      }
      FUN_08021d60(&local_40,0,iVar5);
    }
    if ((local_80 != 0) && (*local_40 != '0')) {
      FUN_08017fc8(&local_40,local_40,0x2d);
    }
    if (local_54 != 0) {
      if (local_90 == 0) {
        local_88 = uVar11;
      }
      FUN_08017ede(&local_58,local_88 & 0xff);
      iVar5 = FUN_0801fe7c(*(undefined4 *)(iVar8 + 8),*(undefined4 *)(iVar8 + 0xc),&local_58);
      if (iVar5 == 0) {
        *puVar2 = *puVar2 | 4;
      }
    }
    if ((local_90 == 0) || (*(uint *)(iVar8 + 0x2c) == uVar11)) {
      FUN_08018180(param_9,&local_40);
      goto LAB_08024722;
    }
  }
LAB_0802462a:
  *puVar2 = *puVar2 | 4;
LAB_08024722:
  local_68 = param_3;
  local_64 = param_4;
  iVar5 = FUN_08012eba(&local_68,&param_5);
  if (iVar5 != 0) {
    *puVar2 = *puVar2 | 2;
  }
  *param_1 = local_68;
  param_1[1] = local_64;
  FUN_08006cec(&local_40);
  FUN_08006cec(&local_58);
  return param_1;
}

