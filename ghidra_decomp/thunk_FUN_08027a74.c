
/* WARNING: Type propagation algorithm not settling */

uint thunk_FUN_08027a74(int param_1,uint param_2,int *param_3,uint *param_4)

{
  longlong lVar1;
  longlong lVar2;
  longlong lVar3;
  bool bVar4;
  uint uVar5;
  undefined4 *puVar6;
  int **ppiVar7;
  int **ppiVar8;
  int **ppiVar9;
  int iVar10;
  undefined4 uVar11;
  int *piVar12;
  uint uVar13;
  uint uVar14;
  uint uVar15;
  int iVar16;
  uint uVar17;
  uint uVar18;
  uint uVar19;
  uint uVar20;
  uint uVar21;
  byte *pbVar22;
  uint uVar23;
  int *piVar24;
  uint uVar25;
  uint uVar26;
  uint uVar27;
  uint uVar28;
  uint uVar29;
  uint uVar30;
  uint uVar31;
  bool bVar32;
  uint uStack_4ac;
  int *apiStack_4a8 [32];
  undefined1 auStack_428 [1028];
  
  bVar4 = false;
  uVar23 = 0;
  for (; iVar16 = *param_3, iVar16 != 0; param_3 = param_3 + 1) {
    if (iVar16 != 0x25) {
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      *(int *)(param_1 + uVar23 * 4) = iVar16;
      uVar23 = uVar23 + 1;
      goto LAB_08027ae6;
    }
    piVar24 = (int *)param_3[1];
    if ((piVar24 == (int *)&Reserved5) || (piVar24 == (int *)0x2b)) {
      param_3 = param_3 + 2;
    }
    else {
      param_3 = param_3 + 1;
      piVar24 = (int *)0x0;
    }
    if (*param_3 - 0x31U < 9) {
      uVar5 = FUN_08029b04(param_3,apiStack_4a8,10);
      param_3 = apiStack_4a8[0];
    }
    else {
      uVar5 = 0;
    }
    if ((*param_3 == 0x45) || (*param_3 == 0x4f)) {
      param_3 = param_3 + 1;
    }
    iVar16 = *param_3;
    uVar11 = DAT_08027ebc;
    uVar13 = uVar23;
    switch(iVar16) {
    case 0x25:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      iVar16 = 0x25;
      goto LAB_0802805e;
    default:
      goto switchD_08027b06_caseD_26;
    case 0x41:
      iVar16 = FUN_08027a54(auStack_428,*(undefined4 *)(DAT_08027ea0 + param_4[6] * 4 + 0x7c),
                            &uStack_4ac);
      puVar6 = (undefined4 *)(iVar16 + -4);
      uVar13 = uVar23 + uStack_4ac;
      for (; uVar13 != uVar23; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        puVar6 = puVar6 + 1;
        *(undefined4 *)(param_1 + uVar23 * 4) = *puVar6;
      }
      goto LAB_08027bda;
    case 0x42:
      iVar16 = FUN_08027a54(auStack_428,*(undefined4 *)(DAT_08027ea0 + (param_4[4] + 0xc) * 4),
                            &uStack_4ac);
      puVar6 = (undefined4 *)(iVar16 + -4);
      uVar13 = uVar23 + uStack_4ac;
      for (; uVar13 != uVar23; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        puVar6 = puVar6 + 1;
        *(undefined4 *)(param_1 + uVar23 * 4) = *puVar6;
      }
      goto LAB_08027bda;
    case 0x43:
      uVar14 = param_4[5];
      bVar32 = (int)uVar14 < DAT_08027ea4;
      if ((int)uVar14 < 0) {
        iVar16 = FUN_0802874c(uVar14 + 0x76c);
        uVar17 = iVar16 / 100;
      }
      else {
        uVar17 = (int)uVar14 / 100 + 0x13;
      }
      uVar15 = DAT_08027ea8;
      uVar11 = DAT_08027eb0;
      if (((piVar24 != (int *)0x0) && (uVar11 = DAT_08027eac, 99 < (int)uVar17)) &&
         (piVar24 == (int *)0x2b)) {
        uVar15 = DAT_08027eb8;
      }
      if (uVar5 < 2) {
        uVar5 = 2 - bVar32;
      }
      else {
        uVar5 = uVar5 - bVar32;
      }
      uVar13 = DAT_08027eb4;
      if (DAT_08027ea4 <= (int)uVar14) {
        uVar13 = uVar15;
      }
      goto LAB_08027d98;
    case 0x44:
      uVar17 = param_4[5];
      uVar13 = param_4[4];
      uVar5 = param_4[3];
      if ((int)uVar17 < 0) {
        uVar17 = FUN_0802874c(uVar17 + 0x76c);
      }
      uVar17 = (int)uVar17 % 100;
      uVar11 = DAT_08027ec4;
      uVar13 = uVar13 + 1;
      goto LAB_08027d98;
    case 0x46:
      apiStack_4a8[0] = (int *)0x25;
      ppiVar8 = apiStack_4a8 + 2;
      if (piVar24 == (int *)0x0) {
        apiStack_4a8[1] = (int *)0x2b;
        iVar16 = 4;
      }
      else {
        uVar11 = DAT_08027ec8;
        apiStack_4a8[1] = piVar24;
        if ((uVar5 < 6) || (iVar16 = uVar5 - 6, iVar16 == 0)) goto LAB_08027df0;
      }
      iVar16 = FUN_0802c270(ppiVar8,0x1e,DAT_08027ecc,iVar16);
      uVar11 = DAT_08027ec8;
      if (0 < iVar16) {
        ppiVar8 = ppiVar8 + iVar16;
      }
      goto LAB_08027df0;
    case 0x47:
      uVar13 = param_4[5];
      bVar32 = (int)uVar13 < DAT_080281d0;
      iVar16 = FUN_080279b0(param_4);
      if ((int)uVar13 < 0) {
        iVar10 = FUN_0802874c(uVar13 + 0x76c);
        iVar10 = iVar10 / 100;
      }
      else {
        iVar10 = (int)uVar13 / 100 + 0x13;
      }
      uVar17 = param_4[5];
      if ((int)uVar17 < 0) {
        uVar17 = FUN_0802874c(uVar17 + 0x76c);
      }
      if (iVar16 == -1) {
        if ((int)param_4[5] < DAT_080281d4) {
          iVar16 = 1;
          bVar32 = true;
        }
      }
      else if (iVar16 == 1) {
        if ((int)uVar13 < DAT_080281d0) {
          iVar16 = -1;
          bVar32 = true;
        }
        else {
          bVar32 = false;
        }
      }
      else {
        iVar16 = 0;
      }
      iVar16 = iVar16 + (int)uVar17 % 100;
      if (iVar16 == -1) {
        iVar10 = iVar10 + -1;
        iVar16 = 99;
      }
      else if (iVar16 == 100) {
        iVar10 = iVar10 + 1;
        iVar16 = 0;
      }
      uVar13 = iVar10 * 100 + iVar16;
      ppiVar8 = apiStack_4a8;
      if (bVar32) {
        piVar12 = (int *)0x2d;
LAB_08027f5a:
        iVar16 = 1;
        ppiVar7 = apiStack_4a8 + 1;
        apiStack_4a8[0] = piVar12;
      }
      else {
        if ((piVar24 == (int *)0x2b) && (piVar12 = piVar24, 9999 < uVar13)) goto LAB_08027f5a;
        iVar16 = 0;
        ppiVar7 = ppiVar8;
      }
      if (uVar5 != 0) {
        uVar5 = uVar5 - iVar16;
      }
      *ppiVar7 = (int *)0x25;
      if (piVar24 == (int *)0x0) {
        ppiVar9 = ppiVar7 + 1;
      }
      else {
        ppiVar9 = ppiVar7 + 2;
        ppiVar7[1] = (int *)0x30;
      }
      FUN_0802ad80(ppiVar9,DAT_080281d8);
      goto LAB_08027f82;
    case 0x48:
    case 0x6b:
      uVar5 = param_4[2];
      uVar11 = DAT_080281e0;
      if (iVar16 == 0x6b) {
        uVar11 = DAT_080281dc;
      }
      break;
    case 0x49:
    case 0x6c:
      uVar5 = param_4[2];
      if (uVar5 == 0) {
        uVar5 = 0xc;
      }
      else if (uVar5 != 0xc) {
        uVar5 = (int)uVar5 % 0xc;
      }
      uVar11 = DAT_080281dc;
      if (iVar16 == 0x49) {
        uVar11 = DAT_080281e0;
      }
      break;
    case 0x4d:
      uVar5 = param_4[1];
      break;
    case 0x50:
    case 0x70:
      iVar16 = FUN_08027a54(auStack_428,
                            *(undefined4 *)(DAT_080281e8 + (uint)(0xb < (int)param_4[2]) * 4 + 0xa4)
                            ,&uStack_4ac);
      for (uVar5 = 0; uVar13 = uVar23, uVar5 < uStack_4ac; uVar5 = uVar5 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        uVar11 = *(undefined4 *)(iVar16 + uVar5 * 4);
        if (*param_3 == 0x50) {
          uVar11 = FUN_08025ae4();
        }
        *(undefined4 *)(param_1 + uVar23 * 4) = uVar11;
        uVar23 = uVar23 + 1;
      }
      goto LAB_08027bda;
    case 0x52:
      uVar13 = param_4[1];
      uVar5 = param_4[2];
      ppiVar8 = DAT_080281f0;
      goto LAB_08027f82;
    case 0x53:
      uVar5 = *param_4;
      break;
    case 0x54:
      uVar17 = *param_4;
      uVar5 = param_4[1];
      uVar11 = DAT_080284a8;
      uVar13 = param_4[2];
LAB_08027d98:
      iVar16 = FUN_0802c270(param_1 + uVar23 * 4,param_2 - uVar23,uVar11,uVar13,uVar5,uVar17);
      goto LAB_08027d9c;
    case 0x55:
      uVar13 = param_4[7];
      uVar5 = param_4[6];
      goto LAB_08028238;
    case 0x56:
      uVar5 = FUN_080279b0(param_4);
      if (param_4[6] == 0) {
        iVar16 = 6;
      }
      else {
        iVar16 = param_4[6] - 1;
      }
      uVar11 = DAT_08027ebc;
      if (uVar5 != 1) {
        if (uVar5 == 0xffffffff) {
          iVar10 = 0x76b;
          if (-1 < (int)param_4[5]) {
            iVar10 = -0x65;
          }
          uVar5 = param_4[5] + iVar10;
          if (((uVar5 & 3) == 0) && (uVar5 != ((int)uVar5 / 100) * 100)) {
            uVar5 = 1;
          }
          else {
            uVar5 = (uint)((int)uVar5 % 400 == 0);
          }
          if ((int)((iVar16 - param_4[7]) - uVar5) < 5) {
            uVar5 = 0x35;
          }
          else {
            uVar5 = 0x34;
          }
        }
        else {
          uVar5 = (int)((param_4[7] + 10) - iVar16) / 7;
        }
      }
      break;
    case 0x57:
      if (param_4[6] == 0) {
        uVar5 = 6;
      }
      else {
        uVar5 = param_4[6] - 1;
      }
      uVar13 = param_4[7];
LAB_08028238:
      uVar5 = (int)((uVar13 + 7) - uVar5) / 7;
      break;
    case 0x58:
      uVar11 = *(undefined4 *)(DAT_08027ea0 + 0x98);
      goto LAB_08027ca4;
    case 0x59:
      uVar13 = param_4[5];
      if ((int)uVar13 < DAT_080284b8) {
        apiStack_4a8[0] = (int *)0x2d;
        uVar13 = DAT_080284b8 - uVar13;
        piVar12 = apiStack_4a8[0];
LAB_0802835c:
        apiStack_4a8[0] = piVar12;
        iVar16 = 1;
        ppiVar8 = apiStack_4a8 + 1;
      }
      else {
        uVar13 = uVar13 + 0x76c;
        if ((piVar24 == (int *)0x2b) && (piVar12 = piVar24, 9999 < uVar13)) goto LAB_0802835c;
        iVar16 = 0;
        ppiVar8 = apiStack_4a8;
      }
      if (uVar5 != 0) {
        uVar5 = uVar5 - iVar16;
      }
      *ppiVar8 = (int *)0x25;
      if (piVar24 == (int *)0x0) {
        ppiVar7 = ppiVar8 + 1;
      }
      else {
        ppiVar7 = ppiVar8 + 2;
        ppiVar8[1] = (int *)0x30;
      }
      FUN_0802ad80(ppiVar7,DAT_080284bc);
      ppiVar8 = apiStack_4a8;
LAB_08027f82:
      iVar16 = FUN_0802c270(param_1 + uVar23 * 4,param_2 - uVar23,ppiVar8,uVar5,uVar13);
      goto LAB_08027d9c;
    case 0x5a:
      if (-1 < (int)param_4[8]) {
        FUN_08027540();
        if (!bVar4) {
          FUN_08027558();
        }
        iVar10 = *(int *)(DAT_080284c4 + (uint)(0 < (int)param_4[8]) * 4);
        iVar16 = FUN_08005ea0(iVar10);
        pbVar22 = (byte *)(iVar10 + -1);
        uVar5 = iVar16 + uVar23;
        for (; uVar23 != uVar5; uVar23 = uVar23 + 1) {
          if (param_2 - 1 <= uVar23) {
            FUN_0802754c();
            return 0;
          }
          pbVar22 = pbVar22 + 1;
          *(uint *)(param_1 + uVar23 * 4) = (uint)*pbVar22;
        }
        FUN_0802754c();
LAB_0802841e:
        bVar4 = true;
        uVar13 = uVar23;
      }
      goto LAB_08027bda;
    case 0x61:
      iVar16 = FUN_08027a54(auStack_428,*(undefined4 *)(DAT_08027ea0 + (param_4[6] + 0x18) * 4),
                            &uStack_4ac);
      puVar6 = (undefined4 *)(iVar16 + -4);
      uVar13 = uVar23 + uStack_4ac;
      for (; uVar13 != uVar23; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        puVar6 = puVar6 + 1;
        *(undefined4 *)(param_1 + uVar23 * 4) = *puVar6;
      }
      goto LAB_08027bda;
    case 0x62:
    case 0x68:
      iVar16 = FUN_08027a54(auStack_428,*(undefined4 *)(DAT_08027ea0 + param_4[4] * 4),&uStack_4ac);
      puVar6 = (undefined4 *)(iVar16 + -4);
      uVar13 = uVar23 + uStack_4ac;
      for (; uVar23 != uVar13; uVar23 = uVar23 + 1) {
        if (param_2 - 1 <= uVar23) {
          return 0;
        }
        puVar6 = puVar6 + 1;
        *(undefined4 *)(param_1 + uVar23 * 4) = *puVar6;
      }
      goto LAB_08027bda;
    case 99:
      uVar11 = *(undefined4 *)(DAT_08027ea0 + 0xa0);
      goto LAB_08027ca4;
    case 100:
    case 0x65:
      uVar5 = param_4[3];
      uVar11 = DAT_08027ec0;
      if (iVar16 == 100) {
        uVar11 = DAT_08027ebc;
      }
      break;
    case 0x67:
      iVar16 = FUN_080279b0(param_4);
      uVar5 = param_4[5];
      if ((int)uVar5 < 0) {
        iVar10 = FUN_0802874c(uVar5 + 0x76c);
        iVar10 = iVar10 % 100;
        if (iVar16 == -1) {
          if ((int)param_4[5] < DAT_08027ed0) {
LAB_08027e82:
            iVar16 = 1;
          }
        }
        else {
          if (iVar16 != 1) goto LAB_080284a0;
          if (DAT_08027ea4 <= (int)param_4[5]) goto LAB_08027e82;
          iVar16 = -1;
        }
      }
      else {
        iVar10 = (int)uVar5 % 100;
        if (iVar16 != -1) {
          if (iVar16 == 1) goto LAB_08027e82;
LAB_080284a0:
          iVar16 = 0;
        }
      }
      uVar5 = ((iVar16 + iVar10) % 100 + 100U) % 100;
      uVar11 = DAT_08027ebc;
      break;
    case 0x6a:
      uVar5 = param_4[7] + 1;
      uVar11 = DAT_080281e4;
      break;
    case 0x6d:
      uVar5 = param_4[4] + 1;
      break;
    case 0x6e:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      iVar16 = 10;
      goto LAB_0802805e;
    case 0x71:
      uVar5 = (int)param_4[4] / 3 + 1;
      uVar11 = DAT_080281ec;
      break;
    case 0x72:
      uVar11 = *(undefined4 *)(DAT_08027ea0 + 0xe4);
      goto LAB_08027ca4;
    case 0x73:
      if ((int)param_4[8] < 0) {
        uVar5 = 0;
      }
      else {
        FUN_08027540();
        if (!bVar4) {
          FUN_08027558();
        }
        iVar16 = FUN_0802adc4();
        uVar5 = -*(int *)(iVar16 + (uint)(0 < (int)param_4[8]) * 0x28 + 0x28);
        FUN_0802754c();
        bVar4 = true;
      }
      uVar13 = param_4[5];
      uVar17 = uVar13 - 0x45;
      iVar16 = ((int)uVar13 >> 0x1f) - (uint)(uVar13 < 0x45);
      if (iVar16 < 0) {
        bVar32 = 0xfffffffc < uVar17;
        uVar17 = uVar13 - 0x42;
        iVar16 = iVar16 + (uint)bVar32;
      }
      uVar18 = uVar17 >> 2 | iVar16 << 0x1e;
      uVar31 = (int)(uVar13 - 1) / 100;
      uVar19 = uVar18 - uVar31;
      uVar26 = (int)(uVar13 + 299) / 400;
      uVar20 = uVar19 + uVar26;
      uVar13 = (uVar13 - 0x46) * 0x16d;
      uVar21 = uVar20 + uVar13;
      uVar17 = param_4[7];
      lVar1 = (ulonglong)(uVar21 + uVar17) * 0x18;
      uVar14 = (uint)lVar1;
      uVar27 = param_4[2];
      uVar28 = param_4[1];
      lVar2 = (ulonglong)(uVar14 + uVar27) * 0x3c;
      uVar25 = (uint)lVar2;
      lVar3 = (ulonglong)(uVar25 + uVar28) * 0x3c;
      uVar29 = (uint)lVar3;
      uVar15 = *param_4;
      uVar30 = uVar29 + uVar15;
      iVar16 = ((((((((iVar16 >> 2) - ((int)uVar31 >> 0x1f)) - (uint)(uVar18 < uVar31)) +
                    ((int)uVar26 >> 0x1f) + (uint)CARRY4(uVar19,uVar26) +
                    ((int)uVar13 >> 0x1f) + (uint)CARRY4(uVar20,uVar13) +
                   ((int)uVar17 >> 0x1f) + (uint)CARRY4(uVar21,uVar17)) * 0x18 +
                   (int)((ulonglong)lVar1 >> 0x20) +
                  ((int)uVar27 >> 0x1f) + (uint)CARRY4(uVar14,uVar27)) * 0x3c +
                  (int)((ulonglong)lVar2 >> 0x20) +
                 ((int)uVar28 >> 0x1f) + (uint)CARRY4(uVar25,uVar28)) * 0x3c +
                 (int)((ulonglong)lVar3 >> 0x20) +
                ((int)uVar15 >> 0x1f) + (uint)CARRY4(uVar29,uVar15)) - ((int)uVar5 >> 0x1f)) -
               (uint)(uVar30 < uVar5);
      iVar16 = FUN_0802c270(param_1 + uVar23 * 4,param_2 - uVar23,DAT_080281f4,iVar16,uVar30 - uVar5
                            ,iVar16);
      goto LAB_08027d9c;
    case 0x74:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      iVar16 = 9;
      goto LAB_0802805e;
    case 0x75:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      if (param_4[6] == 0) {
        iVar16 = 0x37;
      }
      else {
        iVar16 = param_4[6] + 0x30;
      }
      goto LAB_0802805e;
    case 0x76:
      FUN_0802ad80(apiStack_4a8,DAT_080284ac);
      iVar16 = FUN_0802698c(apiStack_4a8);
      ppiVar8 = apiStack_4a8 + iVar16 + 1;
      if (piVar24 == (int *)0x0) {
        apiStack_4a8[iVar16] = (int *)0x2b;
        iVar16 = 4;
      }
      else {
        apiStack_4a8[iVar16] = piVar24;
        uVar11 = DAT_080284b0;
        if ((uVar5 < 6) || (iVar16 = uVar5 - 6, iVar16 == 0)) goto LAB_08027df0;
      }
      iVar16 = FUN_0802c270(ppiVar8,(int)(auStack_428 + -(int)ppiVar8) >> 2,DAT_080284b4,iVar16);
      uVar11 = DAT_080284b0;
      if (0 < iVar16) {
        ppiVar8 = ppiVar8 + iVar16;
      }
LAB_08027df0:
      ppiVar7 = apiStack_4a8;
      FUN_0802ad80(ppiVar8,uVar11);
      goto LAB_08027cb6;
    case 0x77:
      if (param_2 - 1 <= uVar23) {
        return 0;
      }
      iVar16 = param_4[6] + 0x30;
LAB_0802805e:
      *(int *)(param_1 + uVar23 * 4) = iVar16;
      uVar13 = uVar23 + 1;
      goto LAB_08027bda;
    case 0x78:
      uVar11 = *(undefined4 *)(DAT_08027ea0 + 0x9c);
LAB_08027ca4:
      ppiVar7 = (int **)FUN_08027a54(auStack_428,uVar11,&uStack_4ac);
      if (*ppiVar7 != (int *)0x0) {
LAB_08027cb6:
        iVar16 = FUN_08027a74(param_1 + uVar23 * 4,param_2 - uVar23,ppiVar7,param_4);
        if (iVar16 < 1) {
          return 0;
        }
        uVar13 = uVar23 + iVar16;
      }
      goto LAB_08027bda;
    case 0x79:
      uVar5 = param_4[5];
      if ((int)uVar5 < 0) {
        uVar5 = FUN_0802874c(uVar5 + 0x76c);
      }
      uVar5 = (int)uVar5 % 100;
      uVar11 = DAT_08027ebc;
      break;
    case 0x7a:
      if (-1 < (int)param_4[8]) {
        FUN_08027540();
        if (!bVar4) {
          FUN_08027558();
        }
        iVar16 = FUN_0802adc4();
        iVar16 = -*(int *)(iVar16 + (uint)(0 < (int)param_4[8]) * 0x28 + 0x28);
        FUN_0802754c();
        iVar10 = FUN_08028f22(iVar16 / 0x3c);
        iVar16 = FUN_0802c270(param_1 + uVar23 * 4,param_2 - uVar23,DAT_080284c0,iVar16 / 0xe10,
                              iVar10 % 0x3c);
        if (iVar16 < 0) {
          return 0;
        }
        uVar23 = iVar16 + uVar23;
        if (param_2 <= uVar23) {
          return 0;
        }
        goto LAB_0802841e;
      }
      goto LAB_08027bda;
    }
    iVar16 = FUN_0802c270(param_1 + uVar23 * 4,param_2 - uVar23,uVar11,uVar5);
LAB_08027d9c:
    if ((iVar16 < 0) || (uVar13 = iVar16 + uVar23, param_2 <= iVar16 + uVar23)) {
switchD_08027b06_caseD_26:
      return 0;
    }
LAB_08027bda:
    uVar23 = uVar13;
    if (*param_3 == 0) break;
LAB_08027ae6:
  }
  if (param_2 != 0) {
    *(undefined4 *)(param_1 + uVar23 * 4) = 0;
  }
  return uVar23;
}

