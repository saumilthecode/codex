
/* WARNING: Type propagation algorithm not settling */

uint FUN_08026b34(int param_1,uint param_2,byte *param_3,uint *param_4)

{
  byte bVar1;
  longlong lVar2;
  longlong lVar3;
  longlong lVar4;
  bool bVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined1 uVar9;
  undefined4 uVar10;
  undefined4 *puVar11;
  uint uVar12;
  uint uVar13;
  uint uVar14;
  byte bVar15;
  char cVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  uint uVar22;
  uint uVar23;
  char *pcVar24;
  undefined1 *puVar25;
  int iVar26;
  byte *pbVar27;
  uint uVar28;
  uint uVar29;
  uint uVar30;
  uint uVar31;
  uint uVar32;
  uint uVar33;
  bool bVar34;
  undefined1 local_48 [2];
  undefined1 auStack_46 [30];
  undefined1 auStack_28 [4];
  
  bVar5 = false;
  uVar23 = 0;
  for (; bVar15 = *param_3, bVar15 != 0; param_3 = param_3 + 1) {
    if (bVar15 != 0x25) {
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      *(byte *)(param_1 + uVar23) = bVar15;
      uVar23 = uVar23 + 1;
      goto LAB_08026b9e;
    }
    bVar15 = param_3[1];
    if ((bVar15 == 0x30) || (bVar15 == 0x2b)) {
      param_3 = param_3 + 2;
    }
    else {
      param_3 = param_3 + 1;
      bVar15 = 0;
    }
    if (*param_3 - 0x31 < 9) {
      uVar6 = FUN_08029a04(param_3,local_48);
      param_3 = _local_48;
    }
    else {
      uVar6 = 0;
    }
    if ((*param_3 == 0x45) || (*param_3 == 0x4f)) {
      param_3 = param_3 + 1;
    }
    bVar1 = *param_3;
    uVar10 = DAT_08026f40;
    uVar12 = uVar23;
    switch(bVar1) {
    case 0x25:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      cVar16 = '%';
      goto LAB_080270dc;
    default:
      goto switchD_08026bc0_caseD_26;
    case 0x41:
      iVar8 = *(int *)(DAT_08026f24 + param_4[6] * 4 + 0x7c);
      iVar7 = FUN_08005ea0(iVar8);
      puVar25 = (undefined1 *)(iVar8 + -1);
      uVar12 = uVar23 + iVar7;
      for (; uVar12 != uVar23; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        puVar25 = puVar25 + 1;
        *(undefined1 *)(param_1 + uVar23) = *puVar25;
      }
      goto LAB_08026c8e;
    case 0x42:
      iVar8 = *(int *)(DAT_08026f24 + (param_4[4] + 0xc) * 4);
      iVar7 = FUN_08005ea0(iVar8);
      puVar25 = (undefined1 *)(iVar8 + -1);
      uVar12 = uVar23 + iVar7;
      for (; uVar12 != uVar23; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        puVar25 = puVar25 + 1;
        *(undefined1 *)(param_1 + uVar23) = *puVar25;
      }
      goto LAB_08026c8e;
    case 0x43:
      uVar13 = param_4[5];
      bVar34 = (int)uVar13 < DAT_08026f28;
      if ((int)uVar13 < 0) {
        iVar7 = FUN_0802874c(uVar13 + 0x76c);
        uVar17 = iVar7 / 100;
      }
      else {
        uVar17 = (int)uVar13 / 100 + 0x13;
      }
      uVar10 = DAT_08026f34;
      uVar12 = DAT_08026f2c;
      if (((bVar15 != 0) && (uVar10 = DAT_08026f30, 99 < (int)uVar17)) && (bVar15 == 0x2b)) {
        uVar12 = DAT_08026f3c;
      }
      if (uVar6 < 2) {
        uVar6 = 2 - bVar34;
      }
      else {
        uVar6 = uVar6 - bVar34;
      }
      if ((int)uVar13 < DAT_08026f28) {
        uVar12 = DAT_08026f38;
      }
      goto LAB_08026e2e;
    case 0x44:
      uVar17 = param_4[5];
      uVar12 = param_4[4];
      uVar6 = param_4[3];
      if ((int)uVar17 < 0) {
        uVar17 = FUN_0802874c(uVar17 + 0x76c);
      }
      uVar17 = (int)uVar17 % 100;
      uVar10 = DAT_08026f48;
      uVar12 = uVar12 + 1;
      goto LAB_08026e2e;
    case 0x46:
      iVar7 = (int)local_48 + 2;
      if (bVar15 == 0) {
        _local_48 = (byte *)CONCAT22(auStack_46._0_2_,0x2b25);
        iVar8 = 4;
LAB_08026e90:
        iVar8 = FUN_0802a92c(iVar7,0x1e,DAT_08026f50,iVar8);
        if (0 < iVar8) {
          iVar7 = iVar7 + iVar8;
        }
      }
      else {
        local_48 = (undefined1  [2])CONCAT11(bVar15,0x25);
        if ((5 < uVar6) && (iVar8 = uVar6 - 6, iVar8 != 0)) goto LAB_08026e90;
      }
      FUN_08028656(iVar7,DAT_08026f4c);
      pcVar24 = local_48;
      goto LAB_08026d52;
    case 0x47:
      uVar12 = param_4[5];
      bVar34 = (int)uVar12 < DAT_08027254;
      iVar7 = FUN_08026a90(param_4);
      if ((int)uVar12 < 0) {
        iVar8 = FUN_0802874c(uVar12 + 0x76c);
        iVar8 = iVar8 / 100;
      }
      else {
        iVar8 = (int)uVar12 / 100 + 0x13;
      }
      uVar17 = param_4[5];
      if ((int)uVar17 < 0) {
        uVar17 = FUN_0802874c(uVar17 + 0x76c);
      }
      if (iVar7 == -1) {
        if ((int)param_4[5] < DAT_08027258) {
          iVar7 = 1;
          bVar34 = true;
        }
      }
      else if (iVar7 == 1) {
        if ((int)uVar12 < DAT_08027254) {
          iVar7 = -1;
          bVar34 = true;
        }
        else {
          bVar34 = false;
        }
      }
      else {
        iVar7 = 0;
      }
      iVar7 = iVar7 + (int)uVar17 % 100;
      if (iVar7 == -1) {
        iVar8 = iVar8 + -1;
        iVar7 = 99;
      }
      else if (iVar7 == 100) {
        iVar8 = iVar8 + 1;
        iVar7 = 0;
      }
      uVar12 = iVar8 * 100 + iVar7;
      if (bVar34) {
        uVar9 = 0x2d;
LAB_08026fda:
        _local_48 = (byte *)CONCAT31(stack0xffffffb9,uVar9);
        puVar11 = (undefined4 *)((int)local_48 + 1);
        iVar7 = 1;
      }
      else {
        if ((bVar15 == 0x2b) && (9999 < uVar12)) {
          uVar9 = 0x2b;
          goto LAB_08026fda;
        }
        puVar11 = (undefined4 *)local_48;
        iVar7 = 0;
      }
      if (uVar6 != 0) {
        uVar6 = uVar6 - iVar7;
      }
      *(undefined1 *)puVar11 = 0x25;
      if (bVar15 == 0) {
        puVar25 = (undefined1 *)((int)puVar11 + 1);
      }
      else {
        puVar25 = (undefined1 *)((int)puVar11 + 2);
        *(undefined1 *)((int)puVar11 + 1) = 0x30;
      }
      goto LAB_08026ffc;
    case 0x48:
    case 0x6b:
      uVar6 = param_4[2];
      uVar10 = DAT_08027260;
      if (bVar1 != 0x6b) {
        uVar10 = DAT_08027264;
      }
      break;
    case 0x49:
    case 0x6c:
      uVar6 = param_4[2];
      if (uVar6 == 0) {
        uVar6 = 0xc;
      }
      else if (uVar6 != 0xc) {
        uVar6 = (int)uVar6 % 0xc;
      }
      uVar10 = DAT_08027264;
      if (bVar1 != 0x49) {
        uVar10 = DAT_08027260;
      }
      break;
    case 0x4d:
      uVar6 = param_4[1];
      break;
    case 0x50:
    case 0x70:
      iVar26 = *(int *)(DAT_0802726c + (uint)(0xb < (int)param_4[2]) * 4 + 0xa4);
      iVar8 = FUN_08005ea0(iVar26);
      iVar7 = DAT_08027270;
      uVar12 = uVar23 + iVar8;
      pbVar27 = (byte *)(iVar26 + -1);
      for (; uVar12 != uVar23; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        pbVar27 = pbVar27 + 1;
        bVar15 = *pbVar27;
        if ((*param_3 == 0x50) && ((*(byte *)(iVar7 + (uint)bVar15) & 3) == 1)) {
          bVar15 = bVar15 + 0x20;
        }
        *(byte *)(param_1 + uVar23) = bVar15;
      }
      goto LAB_08026c8e;
    case 0x52:
      uVar12 = param_4[1];
      uVar6 = param_4[2];
      puVar11 = DAT_08027278;
      goto LAB_08027148;
    case 0x53:
      uVar6 = *param_4;
      break;
    case 0x54:
      uVar17 = *param_4;
      uVar6 = param_4[1];
      uVar10 = DAT_08027520;
      uVar12 = param_4[2];
LAB_08026e2e:
      iVar7 = FUN_0802a92c(param_1 + uVar23,param_2 - uVar23,uVar10,uVar12,uVar6,uVar17);
      goto LAB_08026e32;
    case 0x55:
      uVar12 = param_4[7];
      uVar6 = param_4[6];
      goto LAB_080272be;
    case 0x56:
      uVar6 = FUN_08026a90(param_4);
      if (param_4[6] == 0) {
        iVar7 = 6;
      }
      else {
        iVar7 = param_4[6] - 1;
      }
      uVar10 = DAT_08026f40;
      if (uVar6 != 1) {
        if (uVar6 == 0xffffffff) {
          iVar8 = 0x76b;
          if (-1 < (int)param_4[5]) {
            iVar8 = -0x65;
          }
          uVar6 = param_4[5] + iVar8;
          if (((uVar6 & 3) == 0) && (uVar6 != ((int)uVar6 / 100) * 100)) {
            uVar6 = 1;
          }
          else {
            uVar6 = (uint)((int)uVar6 % 400 == 0);
          }
          if ((int)((iVar7 - param_4[7]) - uVar6) < 5) {
            uVar6 = 0x35;
          }
          else {
            uVar6 = 0x34;
          }
        }
        else {
          uVar6 = (int)((param_4[7] + 10) - iVar7) / 7;
        }
      }
      break;
    case 0x57:
      if (param_4[6] == 0) {
        uVar6 = 6;
      }
      else {
        uVar6 = param_4[6] - 1;
      }
      uVar12 = param_4[7];
LAB_080272be:
      uVar6 = (int)((uVar12 + 7) - uVar6) / 7;
      break;
    case 0x58:
      pcVar24 = *(char **)(DAT_08026f24 + 0x98);
      goto LAB_08026d3e;
    case 0x59:
      uVar12 = param_4[5];
      if ((int)uVar12 < DAT_08027530) {
        _local_48 = (byte *)CONCAT31(stack0xffffffb9,0x2d);
        uVar12 = DAT_08027530 - uVar12;
LAB_080273e4:
        iVar7 = 1;
        puVar11 = (undefined4 *)((int)local_48 + 1);
      }
      else {
        uVar12 = uVar12 + 0x76c;
        if ((bVar15 == 0x2b) && (9999 < uVar12)) {
          _local_48 = (byte *)CONCAT31(stack0xffffffb9,0x2b);
          goto LAB_080273e4;
        }
        iVar7 = 0;
        puVar11 = (undefined4 *)local_48;
      }
      if (uVar6 != 0) {
        uVar6 = uVar6 - iVar7;
      }
      *(undefined1 *)puVar11 = 0x25;
      if (bVar15 == 0) {
        puVar25 = (undefined1 *)((int)puVar11 + 1);
      }
      else {
        puVar25 = (undefined1 *)((int)puVar11 + 2);
        *(undefined1 *)((int)puVar11 + 1) = 0x30;
      }
LAB_08026ffc:
      FUN_08028656(puVar25,DAT_0802725c);
      puVar11 = (undefined4 *)local_48;
LAB_08027148:
      iVar7 = FUN_0802a92c(param_1 + uVar23,param_2 - uVar23,puVar11,uVar6,uVar12);
      goto LAB_08026e32;
    case 0x5a:
      if (-1 < (int)param_4[8]) {
        FUN_08027540();
        if (!bVar5) {
          FUN_08027558();
        }
        iVar8 = *(int *)(DAT_08027538 + (uint)(0 < (int)param_4[8]) * 4);
        iVar7 = FUN_08005ea0(iVar8);
        puVar25 = (undefined1 *)(iVar8 + -1);
        uVar6 = iVar7 + uVar23;
        for (; uVar23 != uVar6; uVar23 = uVar23 + 1) {
          if (param_2 - 1 <= uVar23) {
            FUN_0802754c();
            return 0;
          }
          puVar25 = puVar25 + 1;
          *(undefined1 *)(param_1 + uVar23) = *puVar25;
        }
        FUN_0802754c();
LAB_08027496:
        bVar5 = true;
        uVar12 = uVar23;
      }
      goto LAB_08026c8e;
    case 0x61:
      iVar8 = *(int *)(DAT_08026f24 + (param_4[6] + 0x18) * 4);
      iVar7 = FUN_08005ea0(iVar8);
      puVar25 = (undefined1 *)(iVar8 + -1);
      uVar12 = uVar23 + iVar7;
      for (; uVar23 != uVar12; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        puVar25 = puVar25 + 1;
        *(undefined1 *)(param_1 + uVar23) = *puVar25;
      }
      goto LAB_08026c8e;
    case 0x62:
    case 0x68:
      iVar8 = *(int *)(DAT_08026f24 + param_4[4] * 4);
      iVar7 = FUN_08005ea0(iVar8);
      puVar25 = (undefined1 *)(iVar8 + -1);
      uVar12 = uVar23 + iVar7;
      for (; uVar23 != uVar12; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        puVar25 = puVar25 + 1;
        *(undefined1 *)(param_1 + uVar23) = *puVar25;
      }
      goto LAB_08026c8e;
    case 99:
      pcVar24 = *(char **)(DAT_08026f24 + 0xa0);
      goto LAB_08026d3e;
    case 100:
    case 0x65:
      uVar6 = param_4[3];
      if (bVar1 != 100) {
        uVar10 = DAT_08026f44;
      }
      break;
    case 0x67:
      iVar7 = FUN_08026a90(param_4);
      uVar6 = param_4[5];
      if ((int)uVar6 < 0) {
        iVar8 = FUN_0802874c(uVar6 + 0x76c);
        iVar8 = iVar8 % 100;
        if (iVar7 == -1) {
          if ((int)param_4[5] < DAT_08026f54) {
LAB_08026f06:
            iVar7 = 1;
          }
        }
        else {
          if (iVar7 != 1) goto LAB_08027518;
          if (DAT_08026f28 <= (int)param_4[5]) goto LAB_08026f06;
          iVar7 = -1;
        }
      }
      else {
        iVar8 = (int)uVar6 % 100;
        if (iVar7 != -1) {
          if (iVar7 == 1) goto LAB_08026f06;
LAB_08027518:
          iVar7 = 0;
        }
      }
      uVar6 = ((iVar7 + iVar8) % 100 + 100U) % 100;
      uVar10 = DAT_08026f40;
      break;
    case 0x6a:
      uVar6 = param_4[7] + 1;
      uVar10 = DAT_08027268;
      break;
    case 0x6d:
      uVar6 = param_4[4] + 1;
      break;
    case 0x6e:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      cVar16 = '\n';
      goto LAB_080270dc;
    case 0x71:
      uVar6 = (int)param_4[4] / 3 + 1;
      uVar10 = DAT_08027274;
      break;
    case 0x72:
      pcVar24 = *(char **)(DAT_08026f24 + 0xe4);
      goto LAB_08026d3e;
    case 0x73:
      if ((int)param_4[8] < 0) {
        uVar6 = 0;
      }
      else {
        FUN_08027540();
        if (!bVar5) {
          FUN_08027558();
        }
        iVar7 = FUN_0802adc4();
        uVar6 = -*(int *)(iVar7 + (uint)(0 < (int)param_4[8]) * 0x28 + 0x28);
        FUN_0802754c();
        bVar5 = true;
      }
      uVar12 = param_4[5];
      uVar17 = uVar12 - 0x45;
      iVar7 = ((int)uVar12 >> 0x1f) - (uint)(uVar12 < 0x45);
      if (iVar7 < 0) {
        bVar34 = 0xfffffffc < uVar17;
        uVar17 = uVar12 - 0x42;
        iVar7 = iVar7 + (uint)bVar34;
      }
      uVar18 = uVar17 >> 2 | iVar7 << 0x1e;
      uVar30 = (int)(uVar12 - 1) / 100;
      uVar19 = uVar18 - uVar30;
      uVar31 = (int)(uVar12 + 299) / 400;
      uVar20 = uVar19 + uVar31;
      uVar12 = (uVar12 - 0x46) * 0x16d;
      uVar21 = uVar20 + uVar12;
      uVar17 = param_4[7];
      lVar2 = (ulonglong)(uVar21 + uVar17) * 0x18;
      uVar13 = (uint)lVar2;
      uVar28 = param_4[2];
      lVar3 = (ulonglong)(uVar13 + uVar28) * 0x3c;
      uVar14 = (uint)lVar3;
      uVar32 = param_4[1];
      lVar4 = (ulonglong)(uVar14 + uVar32) * 0x3c;
      uVar33 = (uint)lVar4;
      uVar29 = *param_4;
      uVar22 = uVar33 + uVar29;
      iVar8 = uVar22 - uVar6;
      iVar7 = FUN_0802a92c(param_1 + uVar23,param_2 - uVar23,DAT_0802727c,iVar8,iVar8,
                           ((((((((iVar7 >> 2) - ((int)uVar30 >> 0x1f)) - (uint)(uVar18 < uVar30)) +
                                ((int)uVar31 >> 0x1f) + (uint)CARRY4(uVar19,uVar31) +
                                ((int)uVar12 >> 0x1f) + (uint)CARRY4(uVar20,uVar12) +
                               ((int)uVar17 >> 0x1f) + (uint)CARRY4(uVar21,uVar17)) * 0x18 +
                               (int)((ulonglong)lVar2 >> 0x20) +
                              ((int)uVar28 >> 0x1f) + (uint)CARRY4(uVar13,uVar28)) * 0x3c +
                              (int)((ulonglong)lVar3 >> 0x20) +
                             ((int)uVar32 >> 0x1f) + (uint)CARRY4(uVar14,uVar32)) * 0x3c +
                             (int)((ulonglong)lVar4 >> 0x20) +
                            ((int)uVar29 >> 0x1f) + (uint)CARRY4(uVar33,uVar29)) -
                           ((int)uVar6 >> 0x1f)) - (uint)(uVar22 < uVar6));
      goto LAB_08026e32;
    case 0x74:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      cVar16 = '\t';
      goto LAB_080270dc;
    case 0x75:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      if (param_4[6] == 0) {
        cVar16 = '7';
      }
      else {
        cVar16 = (char)param_4[6] + '0';
      }
      goto LAB_080270dc;
    case 0x76:
      pcVar24 = local_48;
      FUN_08028656(pcVar24,DAT_08027524);
      iVar7 = FUN_08005ea0(pcVar24);
      iVar8 = (int)local_48 + iVar7 + 1;
      if (bVar15 == 0) {
        pcVar24[iVar7] = '+';
        iVar7 = 4;
LAB_0802737c:
        iVar7 = FUN_0802a92c(iVar8,auStack_28 + -iVar8,DAT_0802752c,iVar7);
        if (0 < iVar7) {
          iVar8 = iVar8 + iVar7;
        }
      }
      else {
        pcVar24[iVar7] = bVar15;
        if ((5 < uVar6) && (iVar7 = uVar6 - 6, iVar7 != 0)) goto LAB_0802737c;
      }
      FUN_08028656(iVar8,DAT_08027528);
      goto LAB_08026d52;
    case 0x77:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      cVar16 = (char)param_4[6] + '0';
LAB_080270dc:
      *(char *)(param_1 + uVar23) = cVar16;
      uVar12 = uVar23 + 1;
      goto LAB_08026c8e;
    case 0x78:
      pcVar24 = *(char **)(DAT_08026f24 + 0x9c);
LAB_08026d3e:
      FUN_08005ea0(pcVar24);
      if (*pcVar24 != '\0') {
LAB_08026d52:
        iVar7 = FUN_08026b34(param_1 + uVar23,param_2 - uVar23,pcVar24,param_4);
        if (iVar7 < 1) {
          return 0;
        }
        uVar12 = uVar23 + iVar7;
      }
      goto LAB_08026c8e;
    case 0x79:
      uVar6 = param_4[5];
      if ((int)uVar6 < 0) {
        uVar6 = FUN_0802874c(uVar6 + 0x76c);
      }
      uVar6 = (int)uVar6 % 100;
      uVar10 = DAT_08026f40;
      break;
    case 0x7a:
      if (-1 < (int)param_4[8]) {
        FUN_08027540();
        if (!bVar5) {
          FUN_08027558();
        }
        iVar7 = FUN_0802adc4();
        iVar7 = -*(int *)(iVar7 + (uint)(0 < (int)param_4[8]) * 0x28 + 0x28);
        FUN_0802754c();
        iVar8 = FUN_08028f22(iVar7 / 0x3c);
        iVar7 = FUN_0802a92c(param_1 + uVar23,param_2 - uVar23,DAT_08027534,iVar7 / 0xe10,
                             iVar8 % 0x3c);
        if (iVar7 < 0) {
          return 0;
        }
        uVar23 = iVar7 + uVar23;
        if (param_2 <= uVar23) {
          return 0;
        }
        goto LAB_08027496;
      }
      goto LAB_08026c8e;
    }
    iVar7 = FUN_0802a92c(param_1 + uVar23,param_2 - uVar23,uVar10,uVar6);
LAB_08026e32:
    if ((iVar7 < 0) || (uVar12 = iVar7 + uVar23, param_2 <= iVar7 + uVar23)) {
switchD_08026bc0_caseD_26:
      return 0;
    }
LAB_08026c8e:
    uVar23 = uVar12;
    if (*param_3 == 0) break;
LAB_08026b9e:
  }
  if (param_2 != 0) {
    *(undefined1 *)(param_1 + uVar23) = 0;
  }
  return uVar23;
}

