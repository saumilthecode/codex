
undefined4 *
FUN_0801adf4(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
            undefined4 param_5,undefined4 param_6,int param_7,uint *param_8,uint *param_9,
            int param_10,uint *param_11)

{
  int iVar1;
  uint *puVar2;
  uint *puVar3;
  int iVar4;
  undefined4 uVar5;
  uint uVar6;
  undefined4 uVar7;
  undefined4 uVar8;
  byte bVar9;
  ushort uVar10;
  uint uVar11;
  int **ppiVar12;
  uint uVar13;
  int iVar14;
  undefined4 uVar15;
  int iVar16;
  bool bVar17;
  uint local_b4;
  undefined4 local_a0;
  undefined4 uStack_9c;
  undefined4 local_98;
  undefined4 local_94;
  uint local_90;
  uint local_8c;
  int *local_88;
  int *local_84;
  undefined1 auStack_6c [20];
  undefined1 auStack_58 [52];
  
  puVar3 = param_11;
  puVar2 = param_9;
  iVar1 = param_7;
  iVar14 = param_7 + 0x6c;
  local_98 = param_3;
  local_94 = param_4;
  iVar4 = FUN_080190a8(iVar14);
  uVar5 = FUN_08018e8c(iVar14);
  uVar6 = FUN_0802698c(param_10);
  local_90 = 0;
  for (local_b4 = 0;
      (local_98 = param_3, local_94 = param_4, iVar14 = FUN_0800e0fc(&local_98,&param_5),
      uVar13 = local_90, param_4 = local_94, param_3 = local_98, iVar14 != 0 && (local_b4 < uVar6));
      local_b4 = local_b4 + 1) {
    if (local_90 != 0) goto LAB_0801ae5a;
    iVar16 = param_10 + local_b4 * 4;
    iVar14 = FUN_0800e0a0(uVar5,*(undefined4 *)(param_10 + local_b4 * 4));
    if (iVar14 != 0x25) {
      iVar14 = FUN_0800e09a(uVar5,8,*(undefined4 *)(param_10 + local_b4 * 4));
      if (iVar14 == 0) {
        iVar14 = FUN_0800e0a6(uVar5,*(undefined4 *)(param_10 + local_b4 * 4));
        uVar8 = FUN_0800e0b8(&local_98);
        param_3 = local_98;
        iVar16 = FUN_0800e0a6(uVar5,uVar8);
        if (iVar14 != iVar16) {
          iVar14 = FUN_0800e0ac(uVar5,*(undefined4 *)(param_10 + local_b4 * 4));
          uVar8 = FUN_0800e0b8(&local_98);
          param_4 = local_94;
          param_3 = local_98;
          iVar16 = FUN_0800e0ac(uVar5,uVar8);
          bVar17 = iVar14 == iVar16;
          goto LAB_0801b70a;
        }
LAB_0801b7aa:
        FUN_080187b2(param_3);
        param_4 = 0xffffffff;
      }
      else {
        while (local_98 = param_3, local_94 = param_4, iVar14 = FUN_0800e0fc(&local_98,&param_5),
              param_3 = local_98, param_4 = local_94, iVar14 != 0) {
          uVar8 = FUN_0800e0b8(&local_98);
          param_4 = local_94;
          param_3 = local_98;
          iVar14 = FUN_0800e09a(uVar5,8,uVar8);
          if (iVar14 == 0) break;
          FUN_080187b2(param_3);
          param_4 = 0xffffffff;
        }
      }
      goto LAB_0801af48;
    }
    iVar14 = FUN_0800e0a0(uVar5,*(undefined4 *)(iVar16 + 4));
    local_8c = uVar13;
    if ((iVar14 == 0x45) || (iVar14 == 0x4f)) {
      local_b4 = local_b4 + 2;
      iVar14 = FUN_0800e0a0(uVar5,*(undefined4 *)(iVar16 + 8),0);
    }
    else {
      local_b4 = local_b4 + 1;
    }
    switch(iVar14) {
    case 0x25:
      iVar14 = FUN_0800e0b8(&local_98);
      param_4 = local_94;
      param_3 = local_98;
      iVar16 = FUN_0800e0b2(uVar5,0x25);
      bVar17 = iVar16 == iVar14;
LAB_0801b70a:
      if (bVar17) goto LAB_0801b7aa;
    default:
switchD_0801b820_caseD_26:
      local_90 = local_90 | 4;
      break;
    case 0x41:
    case 0x61:
      FUN_08018c2c(iVar4,&local_88);
      FUN_08018c4c(iVar4,auStack_6c);
      FUN_0801a8c8(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,&local_88,0xe,iVar1
                   ,&local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[6] = (int)local_8c % 7;
LAB_0801aedc:
        bVar9 = (byte)*puVar3 | 2;
LAB_0801b0c4:
        *(byte *)puVar3 = bVar9;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 0x42:
    case 0x62:
    case 0x68:
      FUN_08018c6c(iVar4,&local_88);
      FUN_08018caa(iVar4,auStack_58);
      FUN_0801a8c8(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,&local_88,0x18,
                   iVar1,&local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[4] = (int)local_8c % 0xc;
        uVar10 = (ushort)*puVar3 | 0x408;
LAB_0801af46:
        *(ushort *)puVar3 = uVar10;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 0x43:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,99,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar3[1] = local_8c;
        uVar10 = (ushort)*puVar3 | 0x480;
        goto LAB_0801af46;
      }
      break;
    case 0x44:
      ppiVar12 = &local_88;
      FUN_08018820(uVar5,DAT_0801b360 + -9,DAT_0801b360,ppiVar12);
      goto LAB_0801af5a;
    case 0x48:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x17,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[2] = local_8c;
        bVar9 = (byte)*puVar3 & 0xfe;
        goto LAB_0801b0c4;
      }
      break;
    case 0x49:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,1,0xc,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[2] = (int)local_8c % 0xc;
        bVar9 = (byte)*puVar3 | 1;
        goto LAB_0801b0c4;
      }
      break;
    case 0x4d:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x3b,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[1] = local_8c;
      }
      break;
    case 0x52:
      iVar16 = DAT_0801b364 + -6;
      iVar14 = DAT_0801b364;
      goto LAB_0801b2d8;
    case 0x53:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x3c,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        *puVar2 = local_8c;
      }
      break;
    case 0x54:
      iVar16 = DAT_0801b5e8 + -9;
      iVar14 = DAT_0801b5e8;
LAB_0801b2d8:
      ppiVar12 = &local_88;
      FUN_08018820(uVar5,iVar16,iVar14,&local_88);
      goto LAB_0801b2e4;
    case 0x55:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x35,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        uVar11 = (local_8c & 0x3f) << 0x10 | 0x20;
        uVar13 = *puVar3 & 0xffc0ffdf;
LAB_0801b3d0:
        *puVar3 = uVar11 | uVar13;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 0x57:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,0x35,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        uVar11 = (local_8c & 0x3f) << 0x10 | 0x40;
        uVar13 = *puVar3 & 0xffc0ffbf;
        goto LAB_0801b3d0;
      }
      break;
    case 0x58:
      ppiVar12 = *(int ***)(*(int *)(iVar4 + 8) + 0x10);
      goto LAB_0801b2e4;
    case 0x59:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,9999,4,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 != 0) break;
      puVar2[5] = local_8c - 0x76c;
      bVar9 = *(byte *)((int)puVar3 + 1) & 0xf9;
      goto LAB_0801af90;
    case 0x5a:
      uVar8 = FUN_0800e0b8(&local_98);
      param_4 = local_94;
      param_3 = local_98;
      iVar14 = FUN_0800e09a(uVar5,1,uVar8);
      if (iVar14 == 0) goto switchD_0801b820_caseD_26;
      FUN_0801a8c8(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_88,DAT_0801b7d8,0xe,
                   iVar1,&local_90);
      local_98 = local_a0;
      local_94 = uStack_9c;
      iVar14 = FUN_0800e0fc(&local_98,&param_5);
      param_3 = local_98;
      param_4 = local_94;
      if ((iVar14 != 0) &&
         (param_3 = local_98, param_4 = local_94, local_90 == 0 && local_88 == (int *)0x0)) {
        iVar14 = FUN_0800e0b8(&local_98);
        param_4 = local_94;
        param_3 = local_98;
        iVar16 = FUN_0800e0b2(uVar5,0x2d);
        if (iVar16 != iVar14) {
          iVar14 = FUN_0800e0b8(&local_98);
          param_4 = local_94;
          param_3 = local_98;
          iVar16 = FUN_0800e0b2(uVar5,0x2b);
          if (iVar16 != iVar14) break;
        }
        local_98 = param_3;
        local_94 = param_4;
        FUN_0801a826(&local_a0,param_2,param_3,param_4,param_5,param_6,&local_88,0,0x17,2,iVar1,
                     &local_90);
        local_98 = local_a0;
        local_94 = uStack_9c;
        FUN_0801a826(&local_a0,param_2,local_a0,uStack_9c,param_5,param_6,&local_88,0,0x3b,2,iVar1,
                     &local_90);
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 99:
      ppiVar12 = *(int ***)(*(int *)(iVar4 + 8) + 0x18);
LAB_0801af5a:
      FUN_0801adf4(&local_a0,param_2,local_98,local_94,param_5,param_6,iVar1,&local_90,puVar2,
                   ppiVar12,puVar3);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        bVar9 = *(byte *)((int)puVar3 + 1);
LAB_0801af90:
        bVar9 = bVar9 | 4;
LAB_0801b2be:
        *(byte *)((int)puVar3 + 1) = bVar9;
        param_3 = local_a0;
        param_4 = uStack_9c;
      }
      break;
    case 100:
    case 0x65:
      uVar7 = FUN_0800e0b8(&local_98);
      uVar15 = local_94;
      uVar8 = local_98;
      iVar14 = FUN_0800e09a(uVar5,8,uVar7);
      if (iVar14 != 0) {
        FUN_080187b2(uVar8);
        uVar15 = 0xffffffff;
      }
      local_94 = uVar15;
      FUN_0801a826(&local_a0,param_2,local_98,uVar15,param_5,param_6,&local_8c,1,0x1f,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[3] = local_8c;
        uVar10 = (ushort)*puVar3 | 0x410;
        goto LAB_0801af46;
      }
      break;
    case 0x6a:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,1,0x16e,3,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[7] = local_8c - 1;
        bVar9 = (byte)*puVar3 | 4;
        goto LAB_0801b0c4;
      }
      break;
    case 0x6d:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,1,0xc,2,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[4] = local_8c - 1;
        bVar9 = (byte)*puVar3 | 8;
        goto LAB_0801b0c4;
      }
      break;
    case 0x6e:
    case 0x74:
      while (local_98 = param_3, local_94 = param_4, iVar14 = FUN_0800e0fc(&local_98,&param_5),
            param_3 = local_98, param_4 = local_94, iVar14 != 0) {
        uVar8 = FUN_0800e0b8(&local_98);
        param_4 = local_94;
        param_3 = local_98;
        iVar14 = FUN_0800e09a(uVar5,8,uVar8);
        if (iVar14 == 0) break;
        FUN_080187b2(param_3);
        param_4 = 0xffffffff;
      }
      break;
    case 0x70:
      local_88 = *(int **)(*(int *)(iVar4 + 8) + 0x20);
      local_84 = *(int **)(*(int *)(iVar4 + 8) + 0x24);
      if ((((*local_88 == 0) || (*local_84 == 0)) ||
          (FUN_0801a8c8(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,&local_88,2,
                        iVar1,&local_90), param_3 = local_a0, param_4 = uStack_9c, local_90 != 0))
         || (local_8c == 0)) break;
      bVar9 = *(byte *)((int)puVar3 + 1) | 1;
      goto LAB_0801b2be;
    case 0x72:
      ppiVar12 = *(int ***)(*(int *)(iVar4 + 8) + 0x28);
      goto LAB_0801b2e4;
    case 0x77:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,6,1,iVar1,
                   &local_90);
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        puVar2[6] = local_8c;
        goto LAB_0801aedc;
      }
      break;
    case 0x78:
      ppiVar12 = *(int ***)(*(int *)(iVar4 + 8) + 8);
LAB_0801b2e4:
      FUN_0801adf4(&local_a0,param_2,local_98,local_94,param_5,param_6,iVar1,&local_90,puVar2,
                   ppiVar12,puVar3);
      param_3 = local_a0;
      param_4 = uStack_9c;
      break;
    case 0x79:
      FUN_0801a826(&local_a0,param_2,local_98,local_94,param_5,param_6,&local_8c,0,99,2,iVar1,
                   &local_90);
      local_98 = local_a0;
      local_94 = uStack_9c;
      param_3 = local_a0;
      param_4 = uStack_9c;
      if (local_90 == 0) {
        *(byte *)((int)puVar3 + 1) = *(byte *)((int)puVar3 + 1) & 0xf9 | 6;
        iVar14 = FUN_0800e0fc(&local_98,&param_5);
        param_3 = local_98;
        param_4 = local_94;
        if (iVar14 == 0) {
LAB_0801b584:
          uVar13 = local_8c;
          if ((int)local_8c < 0x45) {
            uVar13 = local_8c + 100;
          }
        }
        else {
          uVar8 = FUN_0800e0b8(&local_98);
          param_4 = local_94;
          param_3 = local_98;
          iVar14 = FUN_0800e0a0(uVar5,uVar8,0x2a);
          if (9 < (iVar14 - 0x30U & 0xff)) goto LAB_0801b584;
          FUN_080187b2(param_3);
          local_8c = local_8c * 10 + (iVar14 - 0x30U);
          local_94 = 0xffffffff;
          iVar14 = FUN_0800e0fc(&local_98,&param_5);
          param_3 = local_98;
          param_4 = local_94;
          if (iVar14 != 0) {
            uVar8 = FUN_0800e0b8(&local_98);
            param_4 = local_94;
            param_3 = local_98;
            iVar14 = FUN_0800e0a0(uVar5,uVar8,0x2a);
            if ((iVar14 - 0x30U & 0xff) < 10) {
              FUN_080187b2(param_3);
              local_8c = local_8c * 10 + (iVar14 - 0x30U);
              param_4 = 0xffffffff;
            }
          }
          *(byte *)((int)puVar3 + 1) = *(byte *)((int)puVar3 + 1) & 0xfd;
          uVar13 = local_8c - 0x76c;
        }
        puVar2[5] = uVar13;
      }
    }
LAB_0801af48:
  }
  if ((local_90 != 0) || (local_b4 != uVar6)) {
LAB_0801ae5a:
    *param_8 = *param_8 | 4;
  }
  *param_1 = local_98;
  param_1[1] = local_94;
  return param_1;
}

