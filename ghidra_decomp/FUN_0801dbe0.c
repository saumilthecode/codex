
undefined4 *
FUN_0801dbe0(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,undefined4 param_9)

{
  uint *puVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  uint uVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  uint uVar12;
  uint uVar13;
  undefined8 uVar14;
  uint local_68;
  uint local_64;
  uint local_5c;
  undefined4 local_40;
  undefined4 local_3c;
  char *local_34;
  char *local_30;
  undefined4 local_2c;
  
  puVar1 = param_8;
  iVar10 = param_7 + 0x6c;
  local_40 = param_3;
  local_3c = param_4;
  uVar2 = FUN_08018e8c(iVar10);
  iVar10 = FUN_0801956c(iVar10);
  local_30 = DAT_0801de8c;
  uVar8 = *(uint *)(iVar10 + 0x28);
  if ((uVar8 != 0) && (uVar8 = *(uint *)(iVar10 + 0x30), uVar8 != 0)) {
    uVar8 = 1;
  }
  local_34 = DAT_0801de8c;
  if (*(char *)(iVar10 + 0x10) != '\0') {
    FUN_0800aa82(&local_34,0x20);
  }
  iVar11 = 0;
  FUN_0800aa82(&local_30,0x20);
  local_68 = 0;
  local_64 = 0;
  local_2c = *(undefined4 *)(iVar10 + 0x3c);
  uVar13 = 0;
  uVar12 = 0;
  local_5c = 0;
LAB_0801dc50:
  do {
    switch(*(undefined1 *)((int)&local_2c + iVar11)) {
    case 0:
      uVar6 = 1;
      goto LAB_0801dede;
    case 1:
      local_40 = param_3;
      local_3c = param_4;
      iVar4 = FUN_0800e0fc(&local_40,&param_5);
      if (iVar4 == 0) {
        uVar6 = 0;
        param_4 = local_3c;
        param_3 = local_40;
      }
      else {
        uVar7 = FUN_0800e0b8(&local_40);
        param_4 = local_3c;
        param_3 = local_40;
        uVar6 = FUN_0800e09a(uVar2,8,uVar7);
        if (uVar6 != 0) {
          FUN_080187b2(param_3);
          param_4 = 0xffffffff;
        }
      }
LAB_0801dede:
      if (iVar11 == 3) goto LAB_0801dd0a;
      while (local_40 = param_3, local_3c = param_4, iVar4 = FUN_0800e0fc(&local_40,&param_5),
            param_4 = local_3c, param_3 = local_40, iVar4 != 0) {
        uVar7 = FUN_0800e0b8(&local_40);
        param_4 = local_3c;
        param_3 = local_40;
        iVar4 = FUN_0800e09a(uVar2,8,uVar7);
        if (iVar4 == 0) break;
        FUN_080187b2(param_3);
        param_4 = 0xffffffff;
      }
      iVar11 = iVar11 + 1;
      goto LAB_0801def8;
    case 2:
      if (((*(int *)(param_7 + 0xc) << 0x16 < 0) || (1 < local_68)) || (iVar11 == 0)) {
LAB_0801dcb0:
        iVar5 = *(int *)(iVar10 + 0x20);
        iVar4 = 0;
        while (local_40 = param_3, local_3c = param_4, uVar6 = FUN_0800e0fc(&local_40,&param_5),
              param_3 = local_40, param_4 = local_3c, uVar6 != 0) {
          if (iVar4 == iVar5) goto LAB_0801dd02;
          iVar3 = FUN_0800e0b8(&local_40);
          param_3 = local_40;
          if (*(int *)(*(int *)(iVar10 + 0x1c) + iVar4 * 4) != iVar3) goto LAB_0801dcec;
          FUN_080187b2(local_40);
          param_4 = 0xffffffff;
          iVar4 = iVar4 + 1;
        }
        if (iVar4 == iVar5) goto switchD_0801dc5a_default;
LAB_0801dcec:
        param_3 = local_40;
        param_4 = local_3c;
        if (iVar4 == 0) {
          uVar6 = ((uint)*(byte *)(param_7 + 0xd) << 0x1e) >> 0x1f ^ 1;
        }
        else {
          uVar6 = 0;
        }
        break;
      }
      if (iVar11 == 1) {
        if (((uVar8 != 0) || ((char)local_2c == '\x03')) || (local_2c._2_1_ == '\x01'))
        goto LAB_0801dcb0;
        iVar11 = 2;
      }
      else {
        if (iVar11 != 2) {
          uVar6 = 1;
          goto LAB_0801dd0a;
        }
        if (local_2c._3_1_ == '\x04') goto LAB_0801dcb0;
        if (uVar8 != 0) {
          if (local_2c._3_1_ == '\x03') goto LAB_0801dcb0;
          iVar11 = 3;
          uVar6 = uVar8;
          goto LAB_0801def8;
        }
        iVar11 = 3;
      }
      goto LAB_0801dc50;
    case 3:
      if (((*(int *)(iVar10 + 0x28) == 0) ||
          (local_40 = param_3, local_3c = param_4, uVar6 = FUN_0800e0fc(&local_40,&param_5),
          param_4 = local_3c, param_3 = local_40, uVar6 == 0)) ||
         (iVar4 = FUN_0800e0b8(&local_40), param_3 = local_40, param_4 = local_3c,
         **(int **)(iVar10 + 0x24) != iVar4)) {
        if (((*(int *)(iVar10 + 0x30) == 0) ||
            (local_40 = param_3, local_3c = param_4, uVar6 = FUN_0800e0fc(&local_40,&param_5),
            param_4 = local_3c, param_3 = local_40, uVar6 == 0)) ||
           (iVar4 = FUN_0800e0b8(&local_40), param_3 = local_40, param_4 = local_3c,
           **(int **)(iVar10 + 0x2c) != iVar4)) {
          if ((*(int *)(iVar10 + 0x28) == 0) || (*(int *)(iVar10 + 0x30) != 0)) {
            uVar6 = uVar8 ^ 1;
          }
          else {
            local_5c = 1;
            uVar6 = 1;
          }
          break;
        }
        local_68 = *(uint *)(iVar10 + 0x30);
        FUN_080187b2(local_40);
        local_5c = uVar6;
      }
      else {
        local_68 = *(uint *)(iVar10 + 0x28);
        FUN_080187b2(local_40);
      }
      param_4 = 0xffffffff;
      break;
    case 4:
      while (local_40 = param_3, local_3c = param_4, uVar6 = FUN_0800e0fc(&local_40,&param_5),
            uVar6 != 0) {
        iVar4 = FUN_0800e0b8(&local_40);
        param_4 = local_3c;
        param_3 = local_40;
        iVar5 = FUN_080269a2(iVar10 + 0x44,iVar4,10);
        if (iVar5 == 0) {
          if ((*(int *)(iVar10 + 0x14) == iVar4) && (uVar13 == 0)) {
            if (*(int *)(iVar10 + 0x34) < 1) goto LAB_0801de60;
            uVar9 = 0;
            local_64 = uVar12;
            uVar13 = uVar6;
          }
          else {
            if ((*(byte *)(iVar10 + 0x10) == 0) ||
               ((uVar6 = (uint)*(byte *)(iVar10 + 0x10), *(int *)(iVar10 + 0x18) != iVar4 ||
                (uVar6 = uVar13, uVar13 != 0)))) goto LAB_0801de60;
            if (uVar12 == 0) {
              uVar6 = 0;
              goto LAB_0801de60;
            }
            FUN_0800ac3e(&local_34,uVar12 & 0xff);
            uVar9 = 0;
          }
        }
        else {
          FUN_0800ac3e(&local_30,*(undefined1 *)(*DAT_0801de90 + (iVar5 - (iVar10 + 0x40) >> 2)));
          uVar9 = uVar12 + 1;
        }
        FUN_080187b2(param_3);
        param_4 = 0xffffffff;
        uVar12 = uVar9;
      }
      param_4 = local_3c;
      param_3 = local_40;
      uVar6 = 1;
LAB_0801de60:
      iVar4 = FUN_08018910(local_30);
      if (iVar4 == 0) {
        uVar6 = 0;
      }
      else {
        uVar6 = uVar6 & 1;
      }
      break;
    default:
switchD_0801dc5a_default:
      uVar6 = 1;
    }
LAB_0801dd02:
    iVar11 = iVar11 + 1;
    if (iVar11 == 4) {
LAB_0801dd0a:
      if (local_68 < 2) {
        if (uVar6 != 0) goto LAB_0801df7e;
      }
      else if (uVar6 != 0) {
        if (local_5c == 0) {
          iVar11 = *(int *)(iVar10 + 0x24);
        }
        else {
          iVar11 = *(int *)(iVar10 + 0x2c);
        }
        uVar8 = 1;
        break;
      }
      goto LAB_0801df00;
    }
LAB_0801def8:
    if (uVar6 == 0) goto LAB_0801df00;
  } while( true );
LAB_0801dd28:
  local_40 = param_3;
  local_3c = param_4;
  iVar4 = FUN_0800e0fc(&local_40,&param_5);
  param_3 = local_40;
  param_4 = local_3c;
  if (iVar4 == 0) goto LAB_0801df7a;
  if (uVar8 == local_68) goto LAB_0801df7e;
  iVar4 = FUN_0800e0b8(&local_40);
  param_3 = local_40;
  param_4 = local_3c;
  if (*(int *)(iVar11 + uVar8 * 4) != iVar4) goto LAB_0801df00;
  FUN_080187b2(local_40);
  uVar8 = uVar8 + 1;
  param_4 = 0xffffffff;
  goto LAB_0801dd28;
LAB_0801df7a:
  if (uVar8 == local_68) {
LAB_0801df7e:
    uVar8 = FUN_08018910(local_30);
    if (1 < uVar8) {
      uVar14 = FUN_0800a726(&local_30,0x30,0);
      iVar11 = (int)uVar14;
      if (iVar11 != 0) {
        if (iVar11 == -1) {
          iVar11 = FUN_08018910(local_30,(int)((ulonglong)uVar14 >> 0x20),0xffffffff);
          iVar11 = iVar11 + -1;
        }
        FUN_08018918(&local_30,0,iVar11);
      }
    }
    if ((local_5c != 0) && (FUN_0800a904(&local_30), *local_30 != '0')) {
      FUN_0800a904(&local_30);
      FUN_0800a984(&local_30,local_30,0x2d);
    }
    iVar11 = FUN_08018910(local_34);
    if (iVar11 != 0) {
      if (uVar13 == 0) {
        local_64 = uVar12;
      }
      FUN_0800ac3e(&local_34,local_64 & 0xff);
      iVar11 = FUN_0801fbd4(*(undefined4 *)(iVar10 + 8),*(undefined4 *)(iVar10 + 0xc),&local_34);
      if (iVar11 == 0) {
        *puVar1 = *puVar1 | 4;
      }
    }
    if ((uVar13 == 0) || (*(uint *)(iVar10 + 0x34) == uVar12)) {
      FUN_0800a6fc(param_9,&local_30);
      goto LAB_0801e018;
    }
  }
LAB_0801df00:
  *puVar1 = *puVar1 | 4;
LAB_0801e018:
  local_40 = param_3;
  local_3c = param_4;
  iVar10 = FUN_0800e0d6(&local_40,&param_5);
  if (iVar10 != 0) {
    *puVar1 = *puVar1 | 2;
  }
  *param_1 = local_40;
  param_1[1] = local_3c;
  FUN_08018950(local_30);
  FUN_08018950(local_34);
  return param_1;
}

