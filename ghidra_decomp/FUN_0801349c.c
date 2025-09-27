
undefined4 *
FUN_0801349c(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,uint *param_9,
            int param_10,uint *param_11)

{
  int iVar1;
  uint *puVar2;
  byte bVar3;
  undefined1 uVar4;
  int iVar5;
  uint uVar6;
  int iVar7;
  uint uVar8;
  int iVar9;
  ushort uVar10;
  char **ppcVar11;
  uint uVar12;
  int iVar13;
  uint local_ac;
  undefined4 local_a0;
  undefined4 uStack_9c;
  undefined4 local_98;
  undefined4 local_94;
  uint local_90;
  uint local_8c;
  char *local_88;
  char *local_84;
  undefined1 auStack_6c [20];
  undefined1 auStack_58 [52];
  
  puVar2 = param_11;
  iVar1 = param_7;
  iVar13 = param_7 + 0x6c;
  local_98 = param_3;
  local_94 = param_4;
  iVar5 = FUN_0801146c(iVar13);
  iVar13 = FUN_0801126c(iVar13);
  uVar6 = FUN_08005ea0(param_10);
  local_90 = 0;
  for (local_ac = 0;
      (local_98 = param_3, local_94 = param_4, iVar7 = FUN_08012ee0(&local_98,&param_5),
      uVar12 = local_90, param_4 = local_94, param_3 = local_98, iVar7 != 0 && (local_ac < uVar6));
      local_ac = local_ac + 1) {
    if (local_90 != 0) goto LAB_080134fe;
    iVar7 = FUN_08010d04(iVar13,*(undefined1 *)(param_10 + local_ac),0);
    if (iVar7 != 0x25) {
      if ((int)((uint)*(byte *)(*(int *)(iVar13 + 0x18) + (uint)*(byte *)(param_10 + local_ac)) <<
               0x1c) < 0) {
        while ((local_98 = param_3, local_94 = param_4, iVar7 = FUN_08012ee0(&local_98,&param_5),
               param_3 = local_98, param_4 = local_94, iVar7 != 0 &&
               (bVar3 = FUN_08012e9c(&local_98), param_3 = local_98, param_4 = local_94,
               (int)((uint)*(byte *)(*(int *)(iVar13 + 0x18) + (uint)bVar3) << 0x1c) < 0))) {
          FUN_08010bc6(local_98);
          param_4 = 0xffffffff;
        }
      }
      else {
        iVar7 = FUN_08010cdc(iVar13);
        uVar4 = FUN_08012e9c(&local_98);
        param_3 = local_98;
        iVar9 = FUN_08010cdc(iVar13,uVar4);
        if (iVar7 != iVar9) {
          iVar7 = FUN_08010cd6(iVar13,*(undefined1 *)(param_10 + local_ac));
          uVar4 = FUN_08012e9c(&local_98);
          param_4 = local_94;
          param_3 = local_98;
          iVar9 = FUN_08010cd6(iVar13,uVar4);
          if (iVar7 != iVar9) {
            local_90 = local_90 | 4;
            goto LAB_080135dc;
          }
        }
        FUN_08010bc6(param_3);
        param_4 = 0xffffffff;
      }
      goto LAB_080135dc;
    }
    iVar7 = FUN_08010d04(iVar13,*(undefined1 *)(param_10 + local_ac + 1),0);
    local_8c = uVar12;
    if ((iVar7 == 0x45) || (uVar12 = local_ac + 1, iVar7 == 0x4f)) {
      iVar7 = FUN_08010d04(iVar13,*(undefined1 *)(param_10 + local_ac + 2),0);
      uVar12 = local_ac + 2;
    }
    local_ac = uVar12;
    switch(iVar7) {
    case 0x25:
      uVar12 = FUN_08012e9c(&local_98);
      param_4 = local_94;
      param_3 = local_98;
      uVar8 = FUN_08010ce2(iVar13,0x25);
      if (uVar8 != (uVar12 & 0xff)) goto switchD_08013ebc_caseD_26;
      FUN_08010bc6(param_3);
      param_4 = 0xffffffff;
      break;
    default:
switchD_08013ebc_caseD_26:
      local_90 = local_90 | 4;
      break;
    case 0x41:
    case 0x61:
      FUN_0801100c(iVar5,&local_88);
      FUN_0801102c(iVar5,auStack_6c);
      FUN_08012f90(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,&local_88,0xe,iVar1
                   ,&local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[6] = (int)local_8c % 7;
LAB_0801356e:
        bVar3 = (byte)*puVar2 | 2;
LAB_08013752:
        *(byte *)puVar2 = bVar3;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 0x42:
    case 0x62:
    case 0x68:
      FUN_0801104c(iVar5,&local_88);
      FUN_0801108a(iVar5,auStack_58);
      FUN_08012f90(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,&local_88,0x18,
                   iVar1,&local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[4] = (int)local_8c % 0xc;
        uVar10 = (ushort)*puVar2 | 0x408;
LAB_080135d8:
        *(ushort *)puVar2 = uVar10;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 0x43:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,99,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[1] = local_8c;
        uVar10 = (ushort)*puVar2 | 0x480;
        goto LAB_080135d8;
      }
      break;
    case 0x44:
      ppcVar11 = &local_88;
      FUN_08010c84(iVar13,DAT_0801399c + -9,DAT_0801399c,ppcVar11);
      goto LAB_080135ec;
    case 0x48:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x17,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[2] = local_8c;
        bVar3 = (byte)*puVar2 & 0xfe;
        goto LAB_08013752;
      }
      break;
    case 0x49:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,1,0xc,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[2] = (int)local_8c % 0xc;
        bVar3 = (byte)*puVar2 | 1;
        goto LAB_08013752;
      }
      break;
    case 0x4d:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x3b,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[1] = local_8c;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 0x52:
      iVar9 = DAT_080139a0 + -6;
      iVar7 = DAT_080139a0;
      goto LAB_08013962;
    case 0x53:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x3c,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        *param_9 = local_8c;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 0x54:
      iVar9 = DAT_08013c70 + -9;
      iVar7 = DAT_08013c70;
LAB_08013962:
      ppcVar11 = &local_88;
      FUN_08010c84(iVar13,iVar9,iVar7,&local_88);
      goto LAB_0801396e;
    case 0x55:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x35,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        uVar8 = (local_8c & 0x3f) << 0x10 | 0x20;
        uVar12 = *puVar2 & 0xffc0ffdf;
LAB_08013a5a:
        *puVar2 = uVar8 | uVar12;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 0x57:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x35,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        uVar8 = (local_8c & 0x3f) << 0x10 | 0x40;
        uVar12 = *puVar2 & 0xffc0ffbf;
        goto LAB_08013a5a;
      }
      break;
    case 0x58:
      ppcVar11 = *(char ***)(*(int *)(iVar5 + 8) + 0x10);
      goto LAB_0801396e;
    case 0x59:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,9999,4,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 != 0) break;
      param_9[5] = local_8c - 0x76c;
      bVar3 = *(byte *)((int)puVar2 + 1) & 0xf9;
      goto LAB_08013622;
    case 0x5a:
      bVar3 = FUN_08012e9c(&local_98);
      param_3 = local_98;
      param_4 = local_94;
      if (-1 < (int)((uint)*(byte *)(*(int *)(iVar13 + 0x18) + (uint)bVar3) << 0x1f))
      goto switchD_08013ebc_caseD_26;
      FUN_08012f90(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_88,DAT_08013e6c,0xe,
                   iVar1,&local_90);
      local_98 = local_a0;
      local_94 = uStack_9c;
      iVar7 = FUN_08012ee0(&local_98,&param_5);
      param_3 = local_98;
      param_4 = local_94;
      if ((iVar7 != 0) && (local_90 == 0 && local_88 == (char *)0x0)) {
        uVar12 = FUN_08012e9c(&local_98);
        param_4 = local_94;
        param_3 = local_98;
        uVar8 = FUN_08010ce2(iVar13,0x2d);
        if (uVar8 != (uVar12 & 0xff)) {
          uVar12 = FUN_08012e9c(&local_98);
          param_4 = local_94;
          param_3 = local_98;
          uVar8 = FUN_08010ce2(iVar13,0x2b);
          if (uVar8 != (uVar12 & 0xff)) break;
        }
        local_98 = param_3;
        local_94 = param_4;
        FUN_08012eee(&local_a0,param_2,param_3,param_4,param_5,param_6,&local_88,0,0x17,2,iVar1,
                     &local_90);
        local_98 = local_a0;
        local_94 = uStack_9c;
        FUN_08012eee(&local_a0,param_2,local_a0,uStack_9c,param_5,param_6,&local_88,0,0x3b,2,iVar1,
                     &local_90);
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 99:
      ppcVar11 = *(char ***)(*(int *)(iVar5 + 8) + 0x18);
LAB_080135ec:
      FUN_0801349c(&local_a0,param_2,local_98,local_94,param_5,param_6,iVar1,&local_90,param_9,
                   ppcVar11,puVar2);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        bVar3 = *(byte *)((int)puVar2 + 1);
LAB_08013622:
        bVar3 = bVar3 | 4;
LAB_08013948:
        *(byte *)((int)puVar2 + 1) = bVar3;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 100:
    case 0x65:
      bVar3 = FUN_08012e9c(&local_98);
      if ((int)((uint)*(byte *)(*(int *)(iVar13 + 0x18) + (uint)bVar3) << 0x1c) < 0) {
        FUN_08010bc6(local_98);
        local_94 = 0xffffffff;
      }
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,1,0x1f,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[3] = local_8c;
        uVar10 = (ushort)*puVar2 | 0x410;
        goto LAB_080135d8;
      }
      break;
    case 0x6a:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,1,0x16e,3,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[7] = local_8c - 1;
        bVar3 = (byte)*puVar2 | 4;
        goto LAB_08013752;
      }
      break;
    case 0x6d:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,1,0xc,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[4] = local_8c - 1;
        bVar3 = (byte)*puVar2 | 8;
        goto LAB_08013752;
      }
      break;
    case 0x6e:
    case 0x74:
      while ((local_98 = param_3, local_94 = param_4, iVar7 = FUN_08012ee0(&local_98,&param_5),
             param_3 = local_98, param_4 = local_94, iVar7 != 0 &&
             (bVar3 = FUN_08012e9c(&local_98), param_3 = local_98, param_4 = local_94,
             (int)((uint)*(byte *)(*(int *)(iVar13 + 0x18) + (uint)bVar3) << 0x1c) < 0))) {
        FUN_08010bc6(local_98);
        param_4 = 0xffffffff;
      }
      break;
    case 0x70:
      local_88 = *(char **)(*(int *)(iVar5 + 8) + 0x20);
      local_84 = *(char **)(*(int *)(iVar5 + 8) + 0x24);
      if ((((*local_88 == '\0') || (*local_84 == '\0')) ||
          (FUN_08012f90(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,&local_88,2,
                        iVar1,&local_90), param_3 = local_a0, param_4 = uStack_9c, local_90 != 0))
         || (param_3 = local_a0, param_4 = uStack_9c, local_8c == 0)) break;
      bVar3 = *(byte *)((int)puVar2 + 1) | 1;
      goto LAB_08013948;
    case 0x72:
      ppcVar11 = *(char ***)(*(int *)(iVar5 + 8) + 0x28);
      goto LAB_0801396e;
    case 0x77:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,6,1,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        param_9[6] = local_8c;
        goto LAB_0801356e;
      }
      break;
    case 0x78:
      ppcVar11 = *(char ***)(*(int *)(iVar5 + 8) + 8);
LAB_0801396e:
      FUN_0801349c(&local_a0,param_2,local_98,local_94,param_5,param_6,iVar1,&local_90,param_9,
                   ppcVar11,puVar2);
      param_3 = local_a0;
      param_4 = uStack_9c;
      break;
    case 0x79:
      FUN_08012eee(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,99,2,iVar1,
                   &local_90);
      local_98 = local_a0;
      local_94 = uStack_9c;
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        *(byte *)((int)puVar2 + 1) = *(byte *)((int)puVar2 + 1) & 0xf9 | 6;
        iVar7 = FUN_08012ee0(&local_98,&param_5);
        param_3 = local_98;
        param_4 = local_94;
        if (iVar7 == 0) {
LAB_08013c0e:
          uVar12 = local_8c;
          if ((int)local_8c < 0x45) {
            uVar12 = local_8c + 100;
          }
        }
        else {
          uVar4 = FUN_08012e9c(&local_98);
          param_4 = local_94;
          param_3 = local_98;
          iVar7 = FUN_08010d04(iVar13,uVar4,0x2a);
          if (9 < (iVar7 - 0x30U & 0xff)) goto LAB_08013c0e;
          FUN_08010bc6(param_3);
          local_8c = local_8c * 10 + (iVar7 - 0x30U);
          local_94 = 0xffffffff;
          iVar7 = FUN_08012ee0(&local_98,&param_5);
          param_3 = local_98;
          param_4 = local_94;
          if (iVar7 != 0) {
            uVar4 = FUN_08012e9c(&local_98);
            param_4 = local_94;
            param_3 = local_98;
            iVar7 = FUN_08010d04(iVar13,uVar4,0x2a);
            if ((iVar7 - 0x30U & 0xff) < 10) {
              FUN_08010bc6(param_3);
              local_8c = local_8c * 10 + (iVar7 - 0x30U);
              param_4 = 0xffffffff;
            }
          }
          *(byte *)((int)puVar2 + 1) = *(byte *)((int)puVar2 + 1) & 0xfd;
          uVar12 = local_8c - 0x76c;
        }
        param_9[5] = uVar12;
      }
    }
LAB_080135dc:
  }
  if ((local_90 != 0) || (local_ac != uVar6)) {
LAB_080134fe:
    *param_8 = *param_8 | 4;
  }
  *param_1 = local_98;
  param_1[1] = local_94;
  return param_1;
}

