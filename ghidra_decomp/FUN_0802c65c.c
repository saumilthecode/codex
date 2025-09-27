
/* WARNING: Heritage AFTER dead removal. Example location: s0xfffffdb0 : 0x0802d274 */
/* WARNING: Type propagation algorithm not settling */
/* WARNING: Restarted to delay deadcode elimination for space: stack */

int FUN_0802c65c(undefined4 *param_1,int *param_2,uint *param_3,uint *param_4)

{
  bool bVar1;
  longlong lVar2;
  bool bVar3;
  bool bVar4;
  bool bVar5;
  bool bVar6;
  bool bVar7;
  bool bVar8;
  undefined4 *puVar9;
  byte *pbVar10;
  int iVar11;
  int *piVar12;
  int *piVar13;
  uint uVar14;
  uint uVar15;
  uint *puVar16;
  int *piVar17;
  int *piVar18;
  int iVar20;
  uint uVar21;
  int iVar22;
  uint *puVar23;
  byte *pbVar24;
  uint uVar25;
  uint *puVar26;
  uint uVar27;
  int iVar28;
  uint *puVar29;
  int iVar30;
  bool bVar31;
  undefined8 uVar32;
  uint *local_2b8;
  uint *local_2b4;
  int local_2ac;
  uint *local_2a8;
  uint *local_2a0;
  uint *local_29c;
  uint *local_298;
  uint *local_294;
  uint *local_290;
  uint *local_28c;
  undefined4 local_288;
  uint local_284;
  int local_280;
  int local_27c;
  byte *local_270;
  uint *local_260;
  uint local_25c;
  uint local_258;
  int local_254;
  uint *local_250;
  uint local_24c;
  undefined4 local_248;
  uint local_244;
  int *local_23c;
  int local_238;
  int local_234;
  uint local_230;
  int local_22c;
  int local_228 [10];
  int aiStack_200 [3];
  undefined1 auStack_1f1 [57];
  uint local_1b8;
  undefined4 local_1b4;
  uint auStack_34 [3];
  uint uStack_28;
  int *piVar19;
  
  local_25c = 0;
  local_24c = 0;
  puVar9 = (undefined4 *)FUN_0802e70c();
  local_258 = (uint)*(byte *)*puVar9;
  if (((int)((uint)*(ushort *)(param_2 + 3) << 0x18) < 0) && (param_2[4] == 0)) {
    iVar20 = FUN_08024a18(param_1,0x40);
    *param_2 = iVar20;
    param_2[4] = iVar20;
    if (iVar20 == 0) {
      *param_1 = 0xc;
      return -1;
    }
    param_2[5] = 0x40;
  }
  local_238 = 0;
  local_234 = 0;
  local_27c = 0;
  local_270 = (byte *)0x0;
  local_2ac = 0;
  local_288 = 0;
  local_284 = 0;
  piVar13 = aiStack_200 + 2;
  local_298 = param_4;
  local_23c = piVar13;
LAB_0802c6ae:
  uVar15 = *param_3;
  puVar29 = param_3;
  if (uVar15 != 0) {
    do {
      if (uVar15 == 0x25) {
        if (param_3 == puVar29) goto LAB_0802c6f8;
        iVar20 = (int)puVar29 - (int)param_3;
        goto LAB_0802c6d0;
      }
      puVar29 = puVar29 + 1;
      uVar15 = *puVar29;
    } while (uVar15 != 0);
    iVar20 = (int)puVar29 - (int)param_3;
    if (param_3 != puVar29) {
LAB_0802c6d0:
      iVar20 = iVar20 >> 2;
      local_234 = local_234 + iVar20;
      local_238 = local_238 + 1;
      *piVar13 = (int)param_3;
      piVar13[1] = iVar20;
      if (7 < local_238) {
        iVar28 = FUN_0802f8f4(param_1,param_2);
        if (iVar28 != 0) goto LAB_0802c828;
        piVar13 = aiStack_200;
      }
      piVar13 = piVar13 + 2;
      local_2ac = local_2ac + iVar20;
LAB_0802c6f8:
      if (*puVar29 != 0) {
        local_260 = (uint *)0x0;
        uVar15 = 0;
        bVar8 = false;
        bVar7 = false;
        bVar6 = false;
        bVar5 = false;
        bVar4 = false;
        bVar3 = false;
        bVar1 = false;
        bVar31 = false;
        local_2a8 = (uint *)0x0;
        uVar21 = puVar29[1];
        local_2b4 = (uint *)0xffffffff;
        param_3 = puVar29 + 1;
LAB_0802c712:
        param_3 = param_3 + 1;
LAB_0802c714:
        local_2b8 = local_2b4;
        uVar27 = uVar15;
        puVar29 = local_2b4;
        switch(uVar21) {
        case 0x20:
          goto switchD_0802c71e_caseD_20;
        default:
          uVar15 = uVar21;
          if (uVar21 != 0) goto LAB_0802c860;
          goto LAB_0802c81e;
        case 0x23:
          uVar21 = *param_3;
          bVar4 = true;
          goto LAB_0802c712;
        case 0x27:
          iVar20 = FUN_0802e70c(param_1);
          local_25c = (uint)**(byte **)(iVar20 + 4);
          iVar20 = FUN_0802e70c(param_1);
          local_270 = *(byte **)(iVar20 + 8);
          uVar21 = *param_3;
          if (((local_25c != 0) && (local_270 != (byte *)0x0)) && (*local_270 != 0)) {
            bVar6 = true;
          }
          goto LAB_0802c712;
        case 0x2a:
          local_2a8 = (uint *)*local_298;
          if ((int)local_2a8 < 0) {
            local_2a8 = (uint *)-(int)local_2a8;
            local_298 = local_298 + 1;
            goto switchD_0802c71e_caseD_2d;
          }
          uVar21 = *param_3;
          local_298 = local_298 + 1;
          goto LAB_0802c712;
        case 0x2b:
          uVar21 = *param_3;
          local_260 = (uint *)0x2b;
          goto LAB_0802c712;
        case 0x2d:
switchD_0802c71e_caseD_2d:
          uVar21 = *param_3;
          uVar15 = uVar15 | 4;
          goto LAB_0802c712;
        case 0x2e:
          puVar29 = param_3 + 1;
          uVar21 = *param_3;
          if (uVar21 == 0x2a) {
            uVar21 = param_3[1];
            local_2b4 = (uint *)(*local_298 | (int)*local_298 >> 0x1f);
            param_3 = puVar29;
            local_298 = local_298 + 1;
            goto LAB_0802c712;
          }
          uVar27 = uVar21 - 0x30;
          if (uVar27 < 10) {
            uVar14 = 0;
            do {
              param_3 = puVar29 + 1;
              uVar21 = *puVar29;
              uVar14 = uVar27 + uVar14 * 10;
              uVar27 = uVar21 - 0x30;
              puVar29 = param_3;
            } while (uVar27 < 10);
            local_2b4 = (uint *)(uVar14 | (int)uVar14 >> 0x1f);
          }
          else {
            local_2b4 = (uint *)0x0;
            param_3 = puVar29;
          }
          goto LAB_0802c714;
        case 0x30:
          uVar21 = *param_3;
          uVar15 = uVar15 | 0x80;
          goto LAB_0802c712;
        case 0x31:
        case 0x32:
        case 0x33:
        case 0x34:
        case 0x35:
        case 0x36:
        case 0x37:
        case 0x38:
        case 0x39:
          goto switchD_0802c71e_caseD_31;
        case 0x41:
        case 0x45:
        case 0x46:
        case 0x47:
        case 0x61:
        case 0x65:
        case 0x66:
        case 0x67:
          puVar9 = (undefined4 *)((int)local_298 + 7U & 0xfffffff8);
          local_298 = puVar9 + 2;
          local_288 = *puVar9;
          local_284 = puVar9[1];
          iVar20 = FUN_0800675c(local_288,local_284 & 0x7fffffff,0xffffffff,DAT_0802cc3c);
          if ((iVar20 == 0) &&
             (iVar20 = FUN_08006720(local_288,local_284 & 0x7fffffff,0xffffffff,DAT_0802cc3c),
             iVar20 == 0)) {
            uVar27 = uVar15 & 0xffffff7f;
            iVar20 = FUN_0800670c(local_288,local_284,0,0);
            if (iVar20 == 0) {
              puVar16 = DAT_0802cc40;
              if (uVar21 < 0x48) {
                puVar16 = DAT_0802cc44;
              }
              if (local_260 != (uint *)0x0) goto LAB_0802dd44;
              local_29c = (uint *)0x3;
              goto LAB_0802c862;
            }
            local_260 = (uint *)0x2d;
            puVar16 = DAT_0802dfac;
            if (0x47 < uVar21) {
              puVar16 = DAT_0802dfa8;
            }
LAB_0802dd44:
            local_2a0 = (uint *)0x0;
            local_29c = (uint *)0x3;
            uVar27 = uVar15 & 0xffffff7f;
            bVar31 = false;
            local_2b8 = (uint *)&Reset;
            puVar29 = local_2a0;
            local_294 = local_2a0;
            local_290 = local_2a0;
            local_28c = local_2a0;
            goto LAB_0802c86e;
          }
          iVar20 = FUN_0800675c(local_288,local_284,local_288,local_284);
          if (iVar20 != 0) {
            uVar27 = uVar15 & 0xffffff7f;
            bVar31 = false;
            if ((local_284 & 0x80000000) != 0) {
              local_260 = (uint *)0x2d;
              puVar16 = DAT_0802e4f0;
              if (0x47 < uVar21) {
                puVar16 = DAT_0802e4e8;
              }
              goto LAB_0802dd44;
            }
            puVar16 = DAT_0802e4e8;
            if (uVar21 < 0x48) {
              puVar16 = DAT_0802e4f0;
            }
            local_294 = (uint *)0x0;
            if (local_260 == (uint *)0x0) {
              local_290 = local_260;
              local_28c = local_260;
              local_2b4 = local_260;
              local_29c = (uint *)0x3;
              local_2a0 = local_260;
              local_2b8 = (uint *)0x3;
              puVar29 = local_2b4;
            }
            else {
              local_290 = (uint *)0x0;
              local_28c = (uint *)0x0;
              local_2b4 = (uint *)0x0;
              local_2a0 = (uint *)0x0;
              local_29c = (uint *)0x3;
              local_2b8 = (uint *)&Reset;
              puVar29 = local_2b4;
            }
            goto LAB_0802c86e;
          }
          if (uVar21 == 0x61) {
            local_244 = 0x78;
LAB_0802dd62:
            local_248 = 0x30;
            bVar5 = true;
            if ((int)local_2b4 < 100) {
              local_2a0 = (uint *)0x0;
            }
            else {
              local_2a0 = (uint *)FUN_08024a18(param_1,((int)local_2b4 + 1) * 4);
              if (local_2a0 == (uint *)0x0) goto LAB_0802dbdc;
            }
            puVar16 = (uint *)FUN_0802c3c4(param_1,&local_1b8,local_288,local_284);
            if (puVar16 == &local_1b8) {
              if ((100 < (int)local_24c) && (local_2a0 == (uint *)0x0)) goto LAB_0802e444;
LAB_0802ddc4:
              local_294 = local_250;
              local_250 = (uint *)((int)local_250 + -1);
              if (uVar21 == 0x61) {
LAB_0802ddd6:
                local_230 = 0x70;
              }
              else {
                if (uVar21 != 0x41) {
                  local_230 = uVar21;
                  puVar23 = local_250;
                  if (-1 < (int)local_250) goto LAB_0802dfce;
                  goto LAB_0802e04e;
                }
                local_230 = 0x50;
              }
            }
            else {
              local_294 = local_250;
              local_250 = (uint *)((int)local_250 + -1);
              if (uVar21 == 0x61) goto LAB_0802ddd6;
              local_230 = 0x50;
              uVar21 = 0x41;
            }
            if ((int)local_250 < 0) {
              local_22c = 0x2d;
              puVar29 = (uint *)(1 - (int)local_294);
            }
            else {
              local_22c = 0x2b;
              puVar29 = local_250;
            }
            if ((int)puVar29 < 10) {
              piVar17 = local_228;
              goto LAB_0802ddf4;
            }
LAB_0802dfda:
            piVar17 = aiStack_200 + 2;
            do {
              piVar12 = piVar17;
              puVar23 = (uint *)((ulonglong)DAT_0802e2ac * ZEXT48(puVar29) >> 0x23);
              piVar12[-1] = (int)puVar29 + (int)puVar23 * -10 + 0x30;
              bVar31 = 99 < (int)puVar29;
              piVar17 = piVar12 + -1;
              puVar29 = puVar23;
            } while (bVar31);
            piVar12[-2] = (int)(puVar23 + 0xc);
            if (piVar12 + -2 < aiStack_200 + 2) {
              piVar17 = &local_22c;
              piVar18 = piVar12 + -2;
              do {
                piVar19 = piVar18 + 1;
                piVar17 = piVar17 + 1;
                *piVar17 = *piVar18;
                piVar18 = piVar19;
              } while ((int *)((int)piVar12 +
                              (((uint)(auStack_1f1 + -(int)piVar12) & 0xfffffffc) - 4)) != piVar19);
              local_27c = (int)(((uint)(auStack_1f1 + -(int)piVar12) & 0xfffffffc) + 0xc) >> 2;
            }
            else {
              local_27c = 2;
            }
          }
          else {
            if (uVar21 == 0x41) {
              local_244 = 0x58;
              goto LAB_0802dd62;
            }
            if (local_2b4 == (uint *)0xffffffff) {
              local_2b4 = (uint *)0x6;
            }
            else if (((uVar21 & 0xffffffdf) == 0x47) && (local_2b4 == (uint *)0x0)) {
              local_2b4 = (uint *)0x1;
            }
            puVar16 = (uint *)FUN_0802c3c4(param_1,&local_1b8,local_288,local_284);
            if ((puVar16 == &local_1b8) && (100 < (int)local_24c)) {
LAB_0802e444:
              uVar32 = FUN_08024a18(param_1,local_24c << 2);
              local_2a0 = (uint *)uVar32;
              if (local_2a0 == (uint *)0x0) goto LAB_0802dbdc;
              puVar16 = (uint *)FUN_0802c3c4(param_1,(int)((ulonglong)uVar32 >> 0x20),local_288,
                                             local_284);
            }
            else {
              local_2a0 = (uint *)0x0;
            }
            puVar29 = local_250;
            local_294 = local_250;
            if (uVar21 == 0x67) {
              if ((int)local_250 + 3 < 0 != SCARRY4((int)local_250,3)) {
                uVar21 = 0x65;
LAB_0802e044:
                local_250 = (uint *)((int)local_250 + -1);
                local_230 = uVar21;
LAB_0802e04e:
                local_22c = 0x2d;
                puVar29 = (uint *)(1 - (int)local_294);
                goto joined_r0x0802e05c;
              }
              if ((int)local_250 <= (int)local_2b4) {
LAB_0802e06a:
                if ((int)local_250 < (int)local_24c) {
                  if ((int)local_250 < 1) {
                    local_29c = (uint *)((2 - (int)local_250) + local_24c);
                  }
                  else {
                    local_29c = (uint *)(local_24c + 1);
                    if (bVar6) goto LAB_0802e15a;
                  }
                }
                else {
                  local_29c = (uint *)((uint)bVar4 + (int)local_250);
                  if ((bVar6) && (0 < (int)local_250)) {
LAB_0802e15a:
                    uVar21 = 0x67;
                    goto LAB_0802e15c;
                  }
                }
                local_2b8 = (uint *)((uint)local_29c & ~((int)local_29c >> 0x1f));
                uVar21 = 0x67;
                goto LAB_0802d576;
              }
              uVar21 = 0x65;
              local_230 = 0x65;
              puVar23 = (uint *)((int)local_250 + -1);
              if (-1 < (int)local_250 + -1) goto LAB_0802dfce;
LAB_0802e13a:
              local_250 = (uint *)((int)local_250 + -1);
              puVar29 = (uint *)(1 - (int)puVar29);
              local_22c = 0x2d;
            }
            else {
              if (uVar21 != 0x47) {
                if ((uVar21 & 0xffffffdf) != 0x46) goto LAB_0802ddc4;
                if ((int)local_250 < 1) {
                  if (bVar4 || local_2b4 != (uint *)0x0) {
                    local_29c = (uint *)((int)local_2b4 + 2);
                    local_2b8 = (uint *)((uint)local_29c & ~((int)local_29c >> 0x1f));
                  }
                  else {
                    local_2b8 = (uint *)0x1;
                    local_29c = (uint *)0x1;
                  }
                }
                else {
                  local_29c = local_294;
                  if (bVar4 || local_2b4 != (uint *)0x0) {
                    local_29c = (uint *)((int)local_2b4 + 1 + (int)local_250);
                  }
                  if (bVar6) {
                    uVar21 = 0x66;
LAB_0802e15c:
                    uVar27 = (uint)*local_270;
                    if (uVar27 != 0xff) {
                      local_28c = (uint *)0x0;
                      local_290 = (uint *)0x0;
                      goto LAB_0802e17a;
                    }
                    local_290 = (uint *)0x0;
                    local_28c = (uint *)0x0;
                    goto LAB_0802e3ca;
                  }
                  local_2b8 = (uint *)((uint)local_29c & ~((int)local_29c >> 0x1f));
                }
                uVar21 = 0x66;
LAB_0802d576:
                local_290 = (uint *)0x0;
                local_28c = (uint *)0x0;
                goto LAB_0802d57e;
              }
              if ((int)local_250 + 3 < 0 != SCARRY4((int)local_250,3)) {
                uVar21 = 0x45;
                goto LAB_0802e044;
              }
              if ((int)local_250 <= (int)local_2b4) goto LAB_0802e06a;
              uVar21 = 0x45;
              local_230 = 0x45;
              puVar23 = (uint *)((int)local_250 + -1);
              if ((int)local_250 + -1 < 0) goto LAB_0802e13a;
LAB_0802dfce:
              local_250 = puVar23;
              local_22c = 0x2b;
              puVar29 = local_250;
              uVar21 = local_230;
joined_r0x0802e05c:
              local_230 = uVar21;
              if (9 < (int)puVar29) goto LAB_0802dfda;
            }
            local_228[0] = 0x30;
            piVar17 = local_228 + 1;
LAB_0802ddf4:
            *piVar17 = (int)(puVar29 + 0xc);
            local_27c = (int)piVar17 + (4 - (int)&local_230) >> 2;
          }
          local_29c = (uint *)(local_27c + local_24c);
          if ((1 < (int)local_24c) || (bVar4)) {
            local_29c = (uint *)((int)local_29c + 1);
          }
          bVar6 = false;
          local_2b8 = (uint *)((uint)local_29c & ~((int)local_29c >> 0x1f));
          local_294 = (uint *)0x0;
          local_290 = (uint *)0x0;
          local_28c = (uint *)0x0;
          goto LAB_0802d57e;
        case 0x43:
        case 99:
          uVar15 = *local_298;
          if (((uVar21 != 99) || (bVar3)) || (uVar15 = FUN_08025804(), uVar15 != 0xffffffff)) {
            local_1b4 = 0;
            local_298 = local_298 + 1;
LAB_0802c860:
            local_1b8 = uVar15;
            local_260 = (uint *)0x0;
            puVar16 = &local_1b8;
            local_29c = (uint *)0x1;
LAB_0802c862:
            bVar31 = false;
            local_2b8 = local_29c;
            puVar29 = local_260;
            local_2a0 = local_260;
            local_294 = local_260;
            local_290 = local_260;
            local_28c = local_260;
            goto LAB_0802c86e;
          }
LAB_0802dbdc:
          uVar15 = *(ushort *)(param_2 + 3) | 0x40;
          *(short *)(param_2 + 3) = (short)uVar15;
          goto LAB_0802c82c;
        case 0x4c:
          uVar21 = *param_3;
          goto LAB_0802c712;
        case 0x53:
        case 0x73:
          puVar29 = local_298 + 1;
          puVar16 = (uint *)*local_298;
          local_260 = (uint *)0x0;
          local_298 = puVar29;
          if (puVar16 == (uint *)0x0) {
            if ((uint *)0x5 < local_2b4) {
              local_2b4 = (uint *)0x6;
            }
            local_2a0 = (uint *)0x0;
            local_294 = (uint *)0x0;
            local_290 = (uint *)0x0;
            local_28c = (uint *)0x0;
            puVar16 = DAT_0802dcb8;
            local_2b8 = local_2b4;
            puVar29 = (uint *)0x0;
            local_29c = local_2b4;
            goto LAB_0802c86e;
          }
          local_29c = local_2b4;
          if ((uVar21 == 0x53) || (bVar3)) {
            if ((int)local_2b4 < 0) {
              local_29c = (uint *)FUN_0802698c(puVar16);
              local_2b8 = (uint *)((uint)local_29c & ~((int)local_29c >> 0x1f));
            }
            else {
              iVar20 = FUN_080269a2(puVar16,0,local_2b4);
              if (iVar20 == 0) {
                local_294 = (uint *)0x0;
                local_2a0 = (uint *)0x0;
                puVar29 = local_294;
                local_290 = local_294;
                local_28c = local_294;
                if (local_260 == (uint *)0x0) {
                }
                else {
                  local_2b8 = (uint *)((int)local_2b4 + 1);
                }
                goto LAB_0802c86e;
              }
              puVar29 = (uint *)(iVar20 - (int)puVar16 >> 2);
              if ((int)puVar29 <= (int)local_2b4) {
                local_29c = puVar29;
              }
              local_2b8 = (uint *)((uint)local_29c & ~((int)local_29c >> 0x1f));
            }
            if (local_260 == (uint *)0x0) {
              local_2a0 = (uint *)0x0;
              local_294 = (uint *)0x0;
              local_290 = (uint *)0x0;
              local_28c = (uint *)0x0;
              puVar29 = (uint *)0x0;
            }
            else {
              local_2b8 = (uint *)((int)local_2b8 + 1);
              local_290 = (uint *)0x0;
              local_28c = (uint *)0x0;
              local_2b4 = (uint *)0x0;
              local_2a0 = (uint *)0x0;
              local_294 = (uint *)0x0;
              puVar29 = local_2b4;
            }
            goto LAB_0802c86e;
          }
          if ((int)local_2b4 < 0) {
            local_29c = (uint *)FUN_08005ea0(puVar16);
          }
          else {
            iVar20 = FUN_08005e00(puVar16,0,local_2b4);
            if (iVar20 != 0) {
              local_29c = (uint *)(iVar20 - (int)puVar16);
            }
          }
          if (local_29c < (uint *)0x64) {
            if (local_29c == (uint *)0x0) {
              puVar23 = &local_1b8;
              local_2a0 = (uint *)0x0;
              puVar29 = puVar23;
              goto LAB_0802ca64;
            }
            local_2a0 = (uint *)0x0;
            puVar29 = &local_1b8;
          }
          else {
            puVar29 = (uint *)FUN_08024a18(param_1,((int)local_29c + 1) * 4);
            local_2a0 = puVar29;
            if (puVar29 == (uint *)0x0) goto LAB_0802dbdc;
          }
          pbVar24 = (byte *)((int)puVar16 + -1);
          puVar23 = puVar29 + -1;
          pbVar10 = pbVar24 + (int)local_29c;
          do {
            pbVar24 = pbVar24 + 1;
            puVar23 = puVar23 + 1;
            *puVar23 = (uint)*pbVar24;
          } while (pbVar24 != pbVar10);
          puVar23 = puVar29 + (int)local_29c;
LAB_0802ca64:
          *puVar23 = 0;
          local_294 = (uint *)0x0;
          puVar16 = puVar29;
          if (local_260 == (uint *)0x0) {
            local_2b4 = local_260;
            local_290 = local_260;
            local_28c = local_260;
            uVar21 = 0x73;
            local_2b8 = local_29c;
            puVar29 = local_2b4;
          }
          else {
            local_2b4 = (uint *)0x0;
            local_2b8 = (uint *)((int)local_29c + 1);
            local_290 = (uint *)0x0;
            local_28c = (uint *)0x0;
            uVar21 = 0x73;
            puVar29 = local_2b4;
          }
          goto LAB_0802c86e;
        case 0x58:
          piVar17 = DAT_0802d624;
          if (!bVar1) goto LAB_0802d5be;
LAB_0802cfec:
          puVar23 = (uint *)((int)local_298 + 7U & 0xfffffff8);
          uVar27 = puVar23[1];
          uVar25 = *puVar23;
          local_298 = puVar23 + 2;
          goto LAB_0802cffa;
        case 100:
        case 0x69:
          if (bVar1) {
            puVar16 = (uint *)((int)local_298 + 7U & 0xfffffff8);
            puVar23 = (uint *)puVar16[1];
            uVar27 = *puVar16;
            local_298 = puVar16 + 2;
          }
          else {
            puVar23 = local_298 + 1;
            uVar27 = *local_298;
            local_298 = puVar23;
            if (bVar3) {
LAB_0802dbf8:
              puVar23 = (uint *)((int)uVar27 >> 0x1f);
            }
            else if (bVar7) {
              puVar23 = (uint *)((int)(uVar27 << 0x10) >> 0x1f);
              uVar27 = (uint)(short)uVar27;
            }
            else {
              if (!bVar8) goto LAB_0802dbf8;
              puVar23 = (uint *)((int)(uVar27 << 0x18) >> 0x1f);
              uVar27 = (uint)(char)uVar27;
            }
          }
          if ((int)puVar23 < 0) {
            bVar31 = uVar27 != 0;
            uVar27 = -uVar27;
            puVar23 = (uint *)(-(int)puVar23 - (uint)bVar31);
            local_260 = (uint *)0x2d;
            if (-1 < (int)local_2b4) {
              uVar15 = uVar15 & 0xffffff7f;
            }
LAB_0802cad4:
            if (puVar23 != (uint *)0x0 || puVar23 < (uint *)(uint)(9 < uVar27)) {
              local_24c = 0;
              puVar26 = &uStack_28;
              goto LAB_0802da76;
            }
LAB_0802cade:
            auStack_34[2] = uVar27 + 0x30;
          }
          else {
            if (((int)local_2b4 < 0) ||
               (uVar15 = uVar15 & 0xffffff7f, uVar27 != 0 || puVar23 != (uint *)0x0))
            goto LAB_0802cad4;
            if (local_2b4 == (uint *)0x0) {
              local_29c = local_2b4;
              puVar16 = &uStack_28;
              goto LAB_0802caf2;
            }
            auStack_34[2] = 0x30;
          }
          if ((int)local_2b4 < 1) {
            local_2b8 = (uint *)0x1;
          }
          local_29c = (uint *)0x1;
          puVar16 = auStack_34 + 2;
          goto LAB_0802caf2;
        case 0x68:
          uVar21 = *param_3;
          if (uVar21 == 0x68) {
            uVar21 = param_3[1];
            bVar8 = true;
            param_3 = param_3 + 1;
          }
          else {
            bVar7 = true;
          }
          goto LAB_0802c712;
        case 0x6a:
        case 0x71:
          uVar21 = *param_3;
          bVar1 = true;
          goto LAB_0802c712;
        case 0x6c:
          uVar21 = *param_3;
          if (uVar21 == 0x6c) {
            uVar21 = param_3[1];
            bVar1 = true;
            param_3 = param_3 + 1;
          }
          else {
            bVar3 = true;
          }
          goto LAB_0802c712;
        case 0x6e:
          if (bVar1) {
            piVar17 = (int *)*local_298;
            *piVar17 = local_2ac;
            piVar17[1] = local_2ac >> 0x1f;
          }
          else if (bVar3) {
LAB_0802dbec:
            *(int *)*local_298 = local_2ac;
          }
          else if (bVar7) {
            *(short *)*local_298 = (short)local_2ac;
          }
          else {
            if (!bVar8) goto LAB_0802dbec;
            *(char *)*local_298 = (char)local_2ac;
          }
          local_298 = local_298 + 1;
          goto LAB_0802c6ae;
        case 0x6f:
          if (bVar1) {
            puVar23 = (uint *)((int)local_298 + 7U & 0xfffffff8);
            uVar14 = puVar23[1];
            uVar25 = *puVar23;
            local_298 = puVar23 + 2;
          }
          else {
            puVar23 = local_298 + 1;
            uVar25 = *local_298;
            uVar14 = 0;
            local_298 = puVar23;
            if (!bVar3) {
              if (bVar7) {
                uVar25 = uVar25 & 0xffff;
                uVar14 = 0;
              }
              else {
                uVar14 = (uint)bVar8 << 9;
                if (bVar8 != 0) {
                  uVar25 = uVar25 & 0xff;
                  uVar14 = 0;
                }
              }
            }
          }
          local_260 = (uint *)0x0;
          if (-1 < (int)local_2b4) {
            uVar27 = uVar15 & 0xfffffb7f;
            bVar6 = false;
            bVar31 = false;
            if ((uVar25 == 0 && uVar14 == 0) && (local_2b4 == (uint *)0x0)) {
              local_2b8 = (uint *)(uint)bVar4;
              if (local_2b8 == (uint *)0x0) {
                local_29c = local_2b4;
                local_290 = local_2b4;
                local_28c = local_2b4;
                local_294 = local_2b4;
                local_2a0 = local_2b4;
                puVar16 = &uStack_28;
              }
              else {
                auStack_34[2] = 0x30;
                local_290 = local_2b4;
                local_28c = local_2b4;
                local_294 = local_2b4;
                local_2a0 = local_2b4;
                puVar16 = auStack_34 + 2;
                local_29c = local_2b8;
              }
              goto LAB_0802c86e;
            }
          }
          bVar6 = false;
          bVar31 = false;
          puVar16 = &uStack_28;
          do {
            puVar23 = puVar16;
            uVar15 = uVar25 & 7;
            uVar25 = uVar25 >> 3 | uVar14 << 0x1d;
            uVar14 = uVar14 >> 3;
            uVar15 = uVar15 + 0x30;
            puVar16 = puVar23 + -1;
            *puVar16 = uVar15;
          } while (uVar25 != 0 || uVar14 != 0);
          if (bVar4) {
            if (uVar15 == 0x30) {
              local_29c = (uint *)((int)&uStack_28 - (int)puVar16 >> 2);
              if ((int)local_2b4 < (int)local_29c) {
                local_2b8 = local_29c;
              }
              local_290 = (uint *)0x0;
              local_28c = (uint *)0x0;
              local_2a0 = (uint *)0x0;
              local_294 = (uint *)0x0;
            }
            else {
              puVar16 = puVar23 + -2;
              local_29c = (uint *)((int)&uStack_28 - (int)puVar16 >> 2);
              puVar23[-2] = 0x30;
              if ((int)local_2b4 < (int)local_29c) {
                local_2b8 = local_29c;
              }
              local_290 = (uint *)0x0;
              local_28c = (uint *)0x0;
              local_2a0 = (uint *)0x0;
              local_294 = (uint *)0x0;
            }
          }
          else {
            local_29c = (uint *)((int)&uStack_28 - (int)puVar16 >> 2);
            if ((int)local_2b4 < (int)local_29c) {
              local_2b8 = local_29c;
            }
            local_2a0 = (uint *)0x0;
            local_294 = (uint *)0x0;
            local_290 = (uint *)0x0;
            local_28c = (uint *)0x0;
          }
          goto LAB_0802c86e;
        case 0x70:
          puVar29 = local_298 + 1;
          uVar25 = *local_298;
          uVar27 = 0;
          local_248 = 0x30;
          local_244 = 0x78;
          local_260 = (uint *)0x0;
          uVar14 = uVar15;
          local_298 = puVar29;
          if (-1 < (int)local_2b4) {
            uVar14 = uVar15 & 0xffffff7f;
            bVar31 = false;
            if (uVar25 == 0) {
              if (local_2b4 == (uint *)0x0) {
                local_29c = local_2b4;
                uVar15 = uVar15 & 4;
                local_290 = local_2b4;
                local_28c = local_2b4;
                local_294 = local_2b4;
                local_2b8 = local_2b4;
                local_2a0 = local_2b4;
                puVar16 = &uStack_28;
                uVar21 = 0x78;
              }
              else {
                uVar15 = uVar15 & 4;
                auStack_34[2] = 0x30;
                local_29c = (uint *)0x1;
                puVar16 = auStack_34 + 2;
                uVar21 = 0x78;
                local_2a0 = (uint *)0x0;
                local_294 = (uint *)0x0;
                local_290 = (uint *)0x0;
                local_28c = (uint *)0x0;
              }
              goto LAB_0802d084;
            }
          }
          bVar5 = true;
          auStack_34[2] = DAT_0802cc48[uVar25 & 0xf];
          uVar21 = 0x78;
          piVar17 = DAT_0802cc48;
          uVar15 = uVar14;
          goto LAB_0802d030;
        case 0x74:
        case 0x7a:
          uVar21 = *param_3;
          goto LAB_0802c712;
        case 0x75:
          if (bVar1) {
            puVar16 = (uint *)((int)local_298 + 7U & 0xfffffff8);
            puVar23 = (uint *)puVar16[1];
            local_298 = puVar16 + 2;
            uVar27 = *puVar16;
            local_260 = (uint *)0x0;
            if ((int)local_2b4 < 0) goto LAB_0802cad4;
            if (uVar27 != 0 || puVar23 != (uint *)0x0) goto LAB_0802cad0;
LAB_0802d4a4:
            uVar27 = uVar15 & 0xffffff7f;
            if (local_2b4 != (uint *)0x0) {
LAB_0802d4ac:
              local_260 = (uint *)0x0;
              uVar15 = uVar15 & 0xffffff7f;
              uVar27 = 0;
              goto LAB_0802cade;
            }
            goto LAB_0802d920;
          }
          puVar23 = local_298 + 1;
          uVar27 = *local_298;
          local_298 = puVar23;
          if (bVar3) {
joined_r0x0802d496:
            if (-1 < (int)local_2b4) {
              puVar23 = (uint *)0x0;
              if (uVar27 == 0) goto LAB_0802d4a4;
LAB_0802cad0:
              local_260 = (uint *)0x0;
              uVar15 = uVar15 & 0xffffff7f;
              goto LAB_0802cad4;
            }
          }
          else {
            if (bVar7) {
              uVar27 = uVar27 & 0xffff;
              goto joined_r0x0802d496;
            }
            if (bVar8) {
              uVar27 = uVar27 & 0xff;
              goto joined_r0x0802d496;
            }
            local_260 = (uint *)0x0;
            if (-1 < (int)local_2b4) {
              bVar31 = false;
              puVar23 = (uint *)0x0;
              if (uVar27 != 0) goto LAB_0802cad0;
              if (local_2b4 != (uint *)0x0) goto LAB_0802d4ac;
              local_290 = local_2b4;
              local_28c = local_2b4;
              local_29c = local_2b4;
              local_294 = local_2b4;
              local_2a0 = local_2b4;
              puVar16 = &uStack_28;
              uVar27 = uVar15 & 0xffffff7f;
              goto LAB_0802c86e;
            }
          }
          local_260 = (uint *)0x0;
          puVar23 = local_260;
          goto LAB_0802cad4;
        case 0x78:
          piVar17 = DAT_0802d2ec;
          if (bVar1) goto LAB_0802cfec;
LAB_0802d5be:
          uVar27 = (uint)bVar1 << 5;
          puVar23 = local_298 + 1;
          uVar25 = *local_298;
          local_298 = puVar23;
          if (!bVar3) {
            if (bVar7) {
              uVar25 = uVar25 & 0xffff;
              uVar27 = 0;
            }
            else {
              uVar27 = (uint)bVar8 << 9;
              if (bVar8 != 0) {
                uVar25 = uVar25 & 0xff;
                uVar27 = 0;
              }
            }
          }
LAB_0802cffa:
          if (bVar4) {
            if (uVar25 == 0 && uVar27 == 0) {
              bVar5 = false;
              if ((int)local_2b4 < 0) {
                auStack_34[2] = *piVar17;
                bVar6 = false;
                puVar16 = auStack_34 + 2;
                goto LAB_0802d05c;
              }
joined_r0x0802d838:
              local_260 = (uint *)0x0;
              if (local_2b4 == (uint *)0x0) {
                uVar27 = uVar15 & 0xfffffb7f;
                bVar6 = false;
LAB_0802d920:
                bVar31 = false;
                local_260 = (uint *)0x0;
                local_2a0 = local_2b4;
                local_290 = local_2b4;
                local_28c = local_2b4;
                local_294 = local_2b4;
                puVar16 = &uStack_28;
                local_29c = local_2a0;
              }
              else {
                bVar6 = false;
                bVar31 = false;
                auStack_34[2] = *piVar17;
                if ((int)local_2b4 < 1) {
                  local_2b8 = (uint *)0x1;
                }
                local_290 = (uint *)0x0;
                local_28c = (uint *)0x0;
                local_2a0 = (uint *)0x0;
                local_29c = (uint *)0x1;
                local_294 = (uint *)0x0;
                puVar16 = auStack_34 + 2;
                uVar27 = uVar15 & 0xfffffb7f;
              }
              goto LAB_0802c86e;
            }
            local_248 = 0x30;
            local_244 = uVar21;
            if ((int)local_2b4 < 0) {
              bVar5 = true;
              goto LAB_0802d890;
            }
            bVar5 = true;
LAB_0802d024:
            bVar6 = false;
            auStack_34[2] = piVar17[uVar25 & 0xf];
            uVar15 = uVar15 & 0xfffffb7f;
          }
          else {
            if (-1 < (int)local_2b4) {
              bVar5 = false;
              if (uVar25 != 0 || uVar27 != 0) goto LAB_0802d024;
              goto joined_r0x0802d838;
            }
LAB_0802d890:
            auStack_34[2] = piVar17[uVar25 & 0xf];
            bVar6 = false;
          }
LAB_0802d030:
          uVar25 = uVar25 >> 4 | uVar27 << 0x1c;
          uVar14 = uVar27 >> 4;
          puVar16 = auStack_34 + 2;
          if (uVar25 != 0 || uVar27 >> 4 != 0) {
            do {
              puVar16 = puVar16 + -1;
              *puVar16 = piVar17[uVar25 & 0xf];
              uVar25 = uVar25 >> 4 | uVar14 << 0x1c;
              uVar14 = uVar14 >> 4;
            } while (uVar25 != 0 || uVar14 != 0);
          }
LAB_0802d05c:
          bVar31 = false;
          local_260 = (uint *)0x0;
          local_29c = (uint *)((int)&uStack_28 - (int)puVar16 >> 2);
          local_290 = (uint *)0x0;
          local_28c = (uint *)0x0;
          if ((int)local_2b4 < (int)local_29c) {
            local_2b8 = local_29c;
          }
          local_2a0 = (uint *)0x0;
          local_294 = (uint *)0x0;
        }
        goto LAB_0802d07a;
      }
    }
  }
LAB_0802c81e:
  if (local_234 == 0) {
LAB_0802c828:
    uVar15 = (uint)*(ushort *)(param_2 + 3);
  }
  else {
    FUN_0802f8f4(param_1,param_2,&local_23c);
    uVar15 = (uint)*(ushort *)(param_2 + 3);
  }
LAB_0802c82c:
  if ((int)(uVar15 << 0x19) < 0) {
    return -1;
  }
  return local_2ac;
LAB_0802da76:
  do {
    uVar14 = (int)puVar23 + CARRY4(uVar27,(uint)puVar23) + uVar27;
    uVar25 = (uint)((ulonglong)DAT_0802dcb4 * (ulonglong)uVar14 >> 0x20);
    local_24c = local_24c + 1;
    puVar26[-1] = uVar27 + ((uVar27 - (uVar14 - ((uVar25 & 0xfffffffc) + (uVar25 >> 2)))) *
                            DAT_0802dcb4 >> 1) * -10 + 0x30;
    puVar16 = puVar26 + -1;
    if (bVar6) {
      while ((*local_270 == local_24c && (local_24c != 0xff))) {
        if (puVar23 == (uint *)0x0 && (uint *)(uint)(9 < uVar27) <= puVar23) goto LAB_0802db5e;
        puVar26[-2] = local_25c;
        if (local_270[1] == 0) {
          uVar14 = (int)puVar23 + CARRY4(uVar27,(uint)puVar23) + uVar27;
          uVar25 = (uint)((ulonglong)DAT_0802dcb4 * (ulonglong)uVar14 >> 0x20);
          uVar14 = uVar14 - ((uVar25 & 0xfffffffc) + (uVar25 >> 2));
          uVar25 = uVar27 - uVar14;
          lVar2 = (ulonglong)uVar25 * (ulonglong)DAT_0802dcb4;
          uVar14 = DAT_0802dcb4 * ((int)puVar23 - (uint)(uVar27 < uVar14)) + uVar25 * -0x33333334 +
                   (int)((ulonglong)lVar2 >> 0x20);
          uVar27 = (uint)lVar2 >> 1 | uVar14 * -0x80000000;
          puVar23 = (uint *)(uVar14 >> 1);
          uVar14 = (int)puVar23 + CARRY4(uVar27,(uint)puVar23) + uVar27;
          uVar25 = (uint)((ulonglong)DAT_0802dcb4 * (ulonglong)uVar14 >> 0x20);
          iVar20 = uVar27 - (uVar14 - ((uVar25 & 0xfffffffc) + (uVar25 >> 2)));
        }
        else {
          uVar14 = (int)puVar23 + CARRY4(uVar27,(uint)puVar23) + uVar27;
          uVar25 = (uint)((ulonglong)DAT_0802dcb4 * (ulonglong)uVar14 >> 0x20);
          uVar14 = uVar14 - ((uVar25 & 0xfffffffc) + (uVar25 >> 2));
          uVar25 = uVar27 - uVar14;
          lVar2 = (ulonglong)uVar25 * (ulonglong)DAT_0802dcb4;
          uVar14 = DAT_0802dcb4 * ((int)puVar23 - (uint)(uVar27 < uVar14)) + uVar25 * -0x33333334 +
                   (int)((ulonglong)lVar2 >> 0x20);
          uVar27 = (uint)lVar2 >> 1 | uVar14 * -0x80000000;
          puVar23 = (uint *)(uVar14 >> 1);
          uVar14 = (int)puVar23 + CARRY4(uVar27,(uint)puVar23) + uVar27;
          uVar25 = (uint)((ulonglong)DAT_0802dcb4 * (ulonglong)uVar14 >> 0x20);
          iVar20 = uVar27 - (uVar14 - ((uVar25 & 0xfffffffc) + (uVar25 >> 2)));
          local_270 = local_270 + 1;
        }
        puVar16 = puVar26 + -3;
        puVar26[-3] = uVar27 + (iVar20 * DAT_0802dcb4 >> 1) * -10 + 0x30;
        puVar26 = puVar26 + -2;
        local_24c = 1;
      }
    }
    uVar14 = (int)puVar23 + CARRY4(uVar27,(uint)puVar23) + uVar27;
    uVar25 = (uint)((ulonglong)DAT_0802dcb4 * (ulonglong)uVar14 >> 0x20);
    uVar14 = uVar14 - ((uVar25 & 0xfffffffc) + (uVar25 >> 2));
    uVar25 = uVar27 - uVar14;
    lVar2 = (ulonglong)uVar25 * (ulonglong)DAT_0802dcb4;
    uVar14 = (int)((ulonglong)lVar2 >> 0x20) +
             DAT_0802dcb4 * ((int)puVar23 - (uint)(uVar27 < uVar14)) + uVar25 * -0x33333334;
    bVar31 = puVar23 != (uint *)0x0;
    bVar1 = puVar23 < (uint *)(uint)(9 < uVar27);
    uVar27 = (uint)lVar2 >> 1 | uVar14 * -0x80000000;
    puVar23 = (uint *)(uVar14 >> 1);
    puVar26 = puVar16;
  } while (bVar31 || bVar1);
LAB_0802db5e:
  local_29c = (uint *)((int)&uStack_28 - (int)puVar16 >> 2);
  local_2b8 = local_2b4;
  if ((int)local_2b4 < (int)local_29c) {
    local_2b8 = local_29c;
  }
LAB_0802caf2:
  bVar31 = false;
  uVar27 = uVar15;
  if (local_260 == (uint *)0x0) {
    local_2a0 = (uint *)0x0;
    local_294 = (uint *)0x0;
    local_290 = (uint *)0x0;
    local_28c = (uint *)0x0;
    goto LAB_0802c86e;
  }
  local_2b8 = (uint *)((int)local_2b8 + 1);
  local_290 = (uint *)0x0;
  local_28c = (uint *)0x0;
  local_2a0 = (uint *)0x0;
  local_294 = (uint *)0x0;
  if (uVar15 == 0) goto LAB_0802cb16;
LAB_0802c87a:
  uVar14 = uVar15;
  if (local_260 != (uint *)0x0) {
LAB_0802c87e:
    uVar27 = 0;
    uVar14 = uVar15;
LAB_0802c886:
    local_238 = local_238 + 1;
    local_234 = local_234 + 1;
    *piVar13 = (int)&local_260;
    piVar13[1] = 1;
    if (7 < local_238) {
      iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
      if (iVar20 != 0) goto LAB_0802cef0;
      piVar13 = aiStack_200;
    }
    piVar13 = piVar13 + 2;
    if (uVar27 != 0) {
LAB_0802c8b0:
      local_238 = local_238 + 1;
      local_234 = local_234 + 2;
      *piVar13 = (int)&local_248;
      piVar13[1] = 2;
      if (local_238 < 8) {
        piVar13 = piVar13 + 2;
      }
      else {
        iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
        if (iVar20 != 0) goto LAB_0802cef0;
        piVar13 = aiStack_200 + 2;
      }
    }
  }
  iVar20 = DAT_0802cfdc;
  if ((uVar15 == 0x80) && (iVar28 = (int)local_2a8 - (int)local_2b8, 0 < iVar28)) {
    if (iVar28 < 0x11) {
      local_280 = DAT_0802e2b4;
    }
    else {
      local_280 = DAT_0802cfdc;
      do {
        while( true ) {
          iVar22 = iVar28;
          local_238 = local_238 + 1;
          local_234 = local_234 + 0x10;
          *piVar13 = iVar20;
          piVar13[1] = 0x10;
          if (local_238 < 8) break;
          iVar28 = FUN_0802f8f4(param_1,param_2,&local_23c);
          if (iVar28 != 0) goto LAB_0802cef0;
          piVar13 = aiStack_200 + 2;
          iVar28 = iVar22 + -0x10;
          if (iVar22 + -0x10 < 0x11) goto LAB_0802ce2e;
        }
        piVar13 = piVar13 + 2;
        iVar28 = iVar22 + -0x10;
      } while (0x10 < iVar22 + -0x10);
LAB_0802ce2e:
      iVar28 = iVar22 + -0x10;
    }
    local_238 = local_238 + 1;
    *piVar13 = local_280;
    local_234 = local_234 + iVar28;
    piVar13[1] = iVar28;
    if (local_238 < 8) {
      piVar13 = piVar13 + 2;
    }
    else {
      iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
      if (iVar20 != 0) goto LAB_0802cef0;
      piVar13 = aiStack_200 + 2;
    }
  }
  goto LAB_0802c8d6;
  while( true ) {
    local_294 = (uint *)((int)local_294 - uVar27);
    uVar27 = (uint)local_270[1];
    if (uVar27 == 0) {
      uVar27 = (uint)*local_270;
      local_28c = (uint *)((int)local_28c + 1);
    }
    else {
      local_290 = (uint *)((int)local_290 + 1);
      local_270 = local_270 + 1;
    }
    if (uVar27 == 0xff) break;
LAB_0802e17a:
    if ((int)local_294 <= (int)uVar27) {
      local_29c = (uint *)((int)local_29c + (int)local_28c + (int)local_290);
      goto LAB_0802e3ca;
    }
  }
  local_29c = (uint *)((int)local_29c + (int)local_290 + (int)local_28c);
LAB_0802e3ca:
  local_2b8 = (uint *)((uint)local_29c & ~((int)local_29c >> 0x1f));
LAB_0802d57e:
  bVar31 = true;
  if (local_254 == 0) {
    local_2b4 = local_260;
    if (local_260 != (uint *)0x0) goto LAB_0802d590;
  }
  else {
    local_260 = (uint *)0x2d;
LAB_0802d590:
    local_2b8 = (uint *)((int)local_2b8 + 1);
    local_2b4 = (uint *)0x0;
  }
LAB_0802d07a:
  uVar27 = uVar15;
  uVar14 = uVar15;
  puVar29 = local_2b4;
  if (!bVar5) {
LAB_0802c86e:
    local_2b4 = puVar29;
    uVar15 = uVar27;
    if (uVar27 != 0) goto LAB_0802c87a;
LAB_0802cb16:
    iVar20 = (int)local_2a8 - (int)local_2b8;
    uVar14 = uVar27;
    if (0 < iVar20) goto LAB_0802d0a8;
    uVar15 = uVar27;
    if (local_260 == (uint *)0x0) goto LAB_0802c8d6;
    goto LAB_0802c87e;
  }
LAB_0802d084:
  local_2b8 = (uint *)((int)local_2b8 + 2);
  if ((uVar15 != 0) || (iVar20 = (int)local_2a8 - (int)local_2b8, iVar20 < 1)) {
    if (local_260 != (uint *)0x0) {
      uVar27 = 2;
      goto LAB_0802c886;
    }
    goto LAB_0802c8b0;
  }
  uVar27 = 2;
LAB_0802d0a8:
  iVar28 = DAT_0802d2f0;
  if (iVar20 < 0x11) {
    local_280 = DAT_0802e2b0;
  }
  else {
    local_280 = DAT_0802d2f0;
    do {
      while( true ) {
        iVar22 = iVar20;
        local_238 = local_238 + 1;
        local_234 = local_234 + 0x10;
        *piVar13 = iVar28;
        piVar13[1] = 0x10;
        if (local_238 < 8) break;
        iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
        if (iVar20 != 0) goto LAB_0802cef0;
        piVar13 = aiStack_200 + 2;
        iVar20 = iVar22 + -0x10;
        if (iVar22 + -0x10 < 0x11) goto LAB_0802d10e;
      }
      piVar13 = piVar13 + 2;
      iVar20 = iVar22 + -0x10;
    } while (0x10 < iVar22 + -0x10);
LAB_0802d10e:
    iVar20 = iVar22 + -0x10;
  }
  local_238 = local_238 + 1;
  *piVar13 = local_280;
  local_234 = iVar20 + local_234;
  piVar13[1] = iVar20;
  if (local_238 < 8) {
    piVar13 = piVar13 + 2;
    if (local_260 != (uint *)0x0) {
      uVar15 = 0;
      goto LAB_0802c886;
    }
    if (uVar27 != 0) {
      uVar15 = 0;
      goto LAB_0802c8b0;
    }
  }
  else {
    iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
    if (iVar20 != 0) goto LAB_0802cef0;
    if (local_260 != (uint *)0x0) {
      piVar13 = aiStack_200 + 2;
      uVar15 = 0;
      goto LAB_0802c886;
    }
    if (uVar27 != 0) {
      piVar13 = aiStack_200 + 2;
      uVar15 = 0;
      goto LAB_0802c8b0;
    }
    piVar13 = aiStack_200 + 2;
  }
LAB_0802c8d6:
  iVar20 = DAT_0802cfdc;
  iVar28 = (int)local_2b4 - (int)local_29c;
  if (0 < iVar28) {
    if (0x10 < iVar28) {
      do {
        while( true ) {
          iVar22 = iVar28;
          local_238 = local_238 + 1;
          local_234 = local_234 + 0x10;
          *piVar13 = DAT_0802cfdc;
          piVar13[1] = 0x10;
          if (local_238 < 8) break;
          iVar28 = FUN_0802f8f4(param_1,param_2,&local_23c);
          if (iVar28 != 0) goto LAB_0802cef0;
          piVar13 = aiStack_200 + 2;
          iVar28 = iVar22 + -0x10;
          if (iVar22 + -0x10 < 0x11) goto LAB_0802ceb8;
        }
        piVar13 = piVar13 + 2;
        iVar28 = iVar22 + -0x10;
      } while (0x10 < iVar22 + -0x10);
LAB_0802ceb8:
      iVar28 = iVar22 + -0x10;
    }
    local_238 = local_238 + 1;
    *piVar13 = iVar20;
    local_234 = local_234 + iVar28;
    piVar13[1] = iVar28;
    if (local_238 < 8) {
      piVar13 = piVar13 + 2;
    }
    else {
      iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
      if (iVar20 != 0) goto LAB_0802cef0;
      piVar13 = aiStack_200 + 2;
    }
  }
  iVar20 = local_234;
  uVar15 = local_24c;
  if (bVar31) {
    if (uVar21 < 0x66) {
      iVar20 = local_234 + 1;
      iVar28 = local_238 + 1;
      piVar17 = piVar13 + 2;
      local_234 = iVar20;
      local_238 = iVar28;
      if ((1 < (int)local_24c) || (bVar4)) {
        *piVar13 = (int)puVar16;
        piVar13[1] = 1;
        if (7 < iVar28) {
          iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
          if (iVar20 != 0) goto LAB_0802cef0;
          piVar17 = aiStack_200 + 2;
        }
        local_238 = local_238 + 1;
        local_234 = local_234 + 1;
        *piVar17 = (int)&local_258;
        piVar17[1] = 1;
        if (7 < local_238) {
          iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
          if (iVar20 != 0) goto LAB_0802cef0;
          piVar17 = aiStack_200;
        }
        iVar20 = local_234;
        iVar28 = local_238;
        piVar17 = piVar17 + 2;
        iVar30 = uVar15 - 1;
        iVar11 = FUN_080066f8(local_288,local_284,0,0);
        iVar22 = DAT_0802d620;
        if (iVar11 == 0) {
          local_238 = iVar28 + 1;
          local_234 = iVar20 + iVar30;
          *piVar17 = (int)(puVar16 + 1);
          piVar17[1] = iVar30;
          if (local_238 < 8) {
LAB_0802cfb6:
            piVar17 = piVar17 + 2;
            iVar28 = local_238;
            iVar20 = local_234;
          }
          else {
LAB_0802d346:
            iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
            if (iVar20 != 0) goto LAB_0802cef0;
            piVar17 = aiStack_200 + 2;
            iVar28 = local_238;
            iVar20 = local_234;
          }
        }
        else if (1 < (int)uVar15) {
          local_238 = iVar28;
          local_234 = iVar20;
          if (0x11 < (int)uVar15) {
            do {
              local_238 = iVar28 + 1;
              local_234 = iVar20 + 0x10;
              *piVar17 = iVar22;
              piVar17[1] = 0x10;
              if (7 < local_238) {
                iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
                if (iVar20 != 0) goto LAB_0802cef0;
                piVar17 = aiStack_200;
              }
              piVar17 = piVar17 + 2;
              iVar30 = iVar30 + -0x10;
              iVar20 = local_234;
              iVar28 = local_238;
            } while (0x10 < iVar30);
          }
          local_238 = local_238 + 1;
          *piVar17 = iVar22;
          local_234 = local_234 + iVar30;
          piVar17[1] = iVar30;
          if (local_238 < 8) goto LAB_0802cfb6;
          goto LAB_0802d346;
        }
      }
      else {
        *piVar13 = (int)puVar16;
        piVar13[1] = 1;
        if (7 < iVar28) goto LAB_0802d346;
      }
      piVar17[1] = local_27c;
      local_238 = iVar28 + 1;
      iVar20 = iVar20 + local_27c;
      *piVar17 = (int)&local_230;
      local_234 = iVar20;
      if (7 < local_238) goto LAB_0802cf20;
      piVar13 = piVar17 + 2;
    }
    else {
      iVar28 = FUN_080066f8(local_288,local_284,0,0);
      uVar15 = local_24c;
      if (iVar28 == 0) {
        if ((int)local_250 < 1) {
          *piVar13 = DAT_0802dcb0;
          local_238 = local_238 + 1;
          local_234 = iVar20 + 1;
          piVar13[1] = 1;
          if (7 < local_238) {
            iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
            if (iVar20 != 0) goto LAB_0802cef0;
            piVar13 = aiStack_200;
          }
          piVar13 = piVar13 + 2;
          if (local_250 == (uint *)0x0) {
            iVar20 = local_234;
            if (!bVar4 && local_24c == 0) goto LAB_0802c912;
            *piVar13 = (int)&local_258;
            piVar13[1] = 1;
            if (7 < local_238 + 1) goto LAB_0802df54;
            piVar13 = piVar13 + 2;
            local_238 = local_238 + 1;
            local_234 = local_234 + 1;
          }
          else {
            *piVar13 = (int)&local_258;
            piVar13[1] = 1;
            iVar20 = local_238 + 1;
            iVar28 = local_234 + 1;
            if (7 < local_238 + 1) {
LAB_0802df54:
              local_234 = local_234 + 1;
              local_238 = local_238 + 1;
              iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
              if (iVar20 != 0) goto LAB_0802cef0;
              piVar13 = aiStack_200;
              iVar20 = local_238;
              iVar28 = local_234;
            }
            local_234 = iVar28;
            local_238 = iVar20;
            iVar20 = DAT_0802e2b4;
            piVar13 = piVar13 + 2;
            if ((int)local_250 < 0) {
              iVar28 = -(int)local_250;
              if ((int)(local_250 + 4) < 0 == SCARRY4((int)local_250,0x10)) {
                local_280 = DAT_0802e4ec;
              }
              else {
                local_280 = DAT_0802e2b4;
                do {
                  local_238 = local_238 + 1;
                  local_234 = local_234 + 0x10;
                  *piVar13 = iVar20;
                  piVar13[1] = 0x10;
                  if (7 < local_238) {
                    iVar22 = FUN_0802f8f4(param_1,param_2,&local_23c);
                    if (iVar22 != 0) goto LAB_0802cef0;
                    piVar13 = aiStack_200;
                  }
                  piVar13 = piVar13 + 2;
                  iVar28 = iVar28 + -0x10;
                } while (0x10 < iVar28);
              }
              local_238 = local_238 + 1;
              *piVar13 = local_280;
              local_234 = local_234 + iVar28;
              piVar13[1] = iVar28;
              if (local_238 < 8) {
                piVar13 = piVar13 + 2;
              }
              else {
                iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
                if (iVar20 != 0) goto LAB_0802cef0;
                piVar13 = aiStack_200 + 2;
              }
            }
          }
          *piVar13 = (int)puVar16;
          local_234 = local_24c + local_234;
          piVar13[1] = local_24c;
          goto joined_r0x0802cf1c;
        }
        puVar29 = (uint *)((int)(local_24c << 2) >> 2);
        if ((int)local_294 <= (int)puVar29) {
          puVar29 = local_294;
        }
        iVar28 = local_24c * 4;
        if (0 < (int)puVar29) {
          local_238 = local_238 + 1;
          local_234 = iVar20 + (int)puVar29;
          *piVar13 = (int)puVar16;
          piVar13[1] = (int)puVar29;
          if (local_238 < 8) {
            piVar13 = piVar13 + 2;
            iVar20 = local_234;
          }
          else {
            iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
            if (iVar20 != 0) goto LAB_0802cef0;
            piVar13 = aiStack_200 + 2;
            iVar20 = local_234;
          }
        }
        iVar22 = DAT_0802d97c;
        puVar23 = local_294;
        if (-1 < (int)puVar29) {
          puVar23 = (uint *)((int)local_294 - (int)puVar29);
        }
        if (0 < (int)puVar23) {
          local_234 = iVar20;
          if ((int)puVar23 < 0x11) {
            local_280 = DAT_0802e4ec;
          }
          else {
            local_280 = DAT_0802d97c;
            do {
              local_238 = local_238 + 1;
              local_234 = local_234 + 0x10;
              *piVar13 = iVar22;
              piVar13[1] = 0x10;
              if (7 < local_238) {
                iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
                if (iVar20 != 0) goto LAB_0802cef0;
                piVar13 = aiStack_200;
              }
              piVar13 = piVar13 + 2;
              puVar23 = puVar23 + -4;
            } while (0x10 < (int)puVar23);
          }
          local_238 = local_238 + 1;
          *piVar13 = local_280;
          local_234 = local_234 + (int)puVar23;
          piVar13[1] = (int)puVar23;
          if (local_238 < 8) {
            piVar13 = piVar13 + 2;
            iVar20 = local_234;
          }
          else {
            iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
            if (iVar20 != 0) goto LAB_0802cef0;
            piVar13 = aiStack_200 + 2;
            iVar20 = local_234;
          }
        }
        local_294 = puVar16 + (int)local_294;
        if (bVar6) {
          do {
            if ((int)local_290 < 1) {
              if ((int)local_28c < 1) goto code_r0x0802d792;
LAB_0802d71c:
              local_28c = (uint *)((int)local_28c + -1);
            }
            else {
              if (0 < (int)local_28c) goto LAB_0802d71c;
              local_290 = (uint *)((int)local_290 + -1);
              local_270 = local_270 + -1;
            }
            *piVar13 = (int)&local_25c;
            local_238 = local_238 + 1;
            local_234 = iVar20 + 1;
            piVar13[1] = 1;
            if (7 < local_238) {
              iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
              if (iVar20 != 0) goto LAB_0802cef0;
              piVar13 = aiStack_200;
            }
            piVar13 = piVar13 + 2;
            uVar27 = (uint)*local_270;
            uVar21 = (int)puVar16 + (iVar28 - (int)local_294) >> 2;
            if ((int)uVar27 <= (int)uVar21) {
              uVar21 = uVar27;
            }
            if (0 < (int)uVar21) {
              local_238 = local_238 + 1;
              local_234 = local_234 + uVar21;
              *piVar13 = (int)local_294;
              piVar13[1] = uVar21;
              if (local_238 < 8) {
                uVar27 = (uint)*local_270;
                piVar13 = piVar13 + 2;
              }
              else {
                iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
                if (iVar20 != 0) goto LAB_0802cef0;
                uVar27 = (uint)*local_270;
                piVar13 = aiStack_200 + 2;
              }
            }
            iVar20 = DAT_0802d97c;
            uVar25 = uVar27;
            if (-1 < (int)uVar21) {
              uVar25 = uVar27 - uVar21;
            }
            if (0 < (int)uVar25) {
              if (0x10 < (int)uVar25) {
                do {
                  while( true ) {
                    uVar21 = uVar25;
                    local_238 = local_238 + 1;
                    local_234 = local_234 + 0x10;
                    *piVar13 = DAT_0802d97c;
                    piVar13[1] = 0x10;
                    if (local_238 < 8) break;
                    iVar22 = FUN_0802f8f4(param_1,param_2,&local_23c);
                    if (iVar22 != 0) goto LAB_0802cef0;
                    piVar13 = aiStack_200 + 2;
                    uVar25 = uVar21 - 0x10;
                    if ((int)(uVar21 - 0x10) < 0x11) goto LAB_0802d8ec;
                  }
                  piVar13 = piVar13 + 2;
                  uVar25 = uVar21 - 0x10;
                } while (0x10 < (int)(uVar21 - 0x10));
LAB_0802d8ec:
                uVar25 = uVar21 - 0x10;
              }
              *piVar13 = iVar20;
              local_238 = local_238 + 1;
              local_234 = local_234 + uVar25;
              piVar13[1] = uVar25;
              if (local_238 < 8) {
                uVar27 = (uint)*local_270;
                piVar13 = piVar13 + 2;
              }
              else {
                iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
                if (iVar20 != 0) goto LAB_0802cef0;
                uVar27 = (uint)*local_270;
                piVar13 = aiStack_200 + 2;
              }
            }
            local_294 = local_294 + uVar27;
            iVar20 = local_234;
          } while( true );
        }
LAB_0802d272:
        if (((int)local_250 < (int)uVar15) || (bVar4)) {
          *piVar13 = (int)&local_258;
          local_238 = local_238 + 1;
          local_234 = iVar20 + 1;
          piVar13[1] = 1;
          if (local_238 < 8) {
            piVar13 = piVar13 + 2;
            iVar20 = local_234;
          }
          else {
            iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
            if (iVar20 != 0) goto LAB_0802cef0;
            piVar13 = aiStack_200 + 2;
            iVar20 = local_234;
          }
        }
        iVar28 = (int)puVar16 + (iVar28 - (int)local_294) >> 2;
        iVar22 = uVar15 - (int)local_250;
        if (iVar22 <= iVar28) {
          iVar28 = iVar22;
        }
        if (0 < iVar28) {
          *piVar13 = (int)local_294;
          piVar13[1] = iVar28;
          local_238 = local_238 + 1;
          local_234 = iVar20 + iVar28;
          if (local_238 < 8) {
            piVar13 = piVar13 + 2;
            iVar20 = local_234;
          }
          else {
            iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
            if (iVar20 != 0) goto LAB_0802cef0;
            piVar13 = aiStack_200 + 2;
            iVar22 = uVar15 - (int)local_250;
            iVar20 = local_234;
          }
        }
        iVar11 = DAT_0802d2f4;
        if (-1 < iVar28) {
          iVar22 = iVar22 - iVar28;
        }
        if (0 < iVar22) {
          if (iVar22 < 0x11) goto LAB_0802e3ee;
          local_280 = DAT_0802d2f4;
          local_234 = iVar20;
          do {
            local_238 = local_238 + 1;
            local_234 = local_234 + 0x10;
            *piVar13 = iVar11;
            piVar13[1] = 0x10;
            if (7 < local_238) {
              iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
              if (iVar20 != 0) goto LAB_0802cef0;
              piVar13 = aiStack_200;
            }
            piVar13 = piVar13 + 2;
            iVar22 = iVar22 + -0x10;
          } while (0x10 < iVar22);
          goto LAB_0802cf08;
        }
      }
      else {
        *piVar13 = DAT_0802cfd8;
        local_238 = local_238 + 1;
        local_234 = iVar20 + 1;
        piVar13[1] = 1;
        if (7 < local_238) {
          iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
          if (iVar20 != 0) goto LAB_0802cef0;
          piVar13 = aiStack_200;
        }
        uVar15 = local_24c;
        piVar13 = piVar13 + 2;
        if (((int)local_250 < (int)local_24c) || (iVar20 = local_234, bVar4)) {
          *piVar13 = (int)&local_258;
          local_238 = local_238 + 1;
          local_234 = local_234 + 1;
          piVar13[1] = 1;
          if (7 < local_238) {
            iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
            if (iVar20 != 0) goto LAB_0802cef0;
            piVar13 = aiStack_200;
          }
          iVar28 = DAT_0802cfdc;
          piVar13 = piVar13 + 2;
          iVar22 = uVar15 - 1;
          iVar20 = local_234;
          if (0 < iVar22) {
            if (iVar22 < 0x11) {
LAB_0802e3ee:
              local_280 = DAT_0802e4ec;
              local_234 = iVar20;
            }
            else {
              local_280 = DAT_0802cfdc;
              do {
                local_238 = local_238 + 1;
                local_234 = local_234 + 0x10;
                *piVar13 = iVar28;
                piVar13[1] = 0x10;
                if (7 < local_238) {
                  iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
                  if (iVar20 != 0) goto LAB_0802cef0;
                  piVar13 = aiStack_200;
                }
                piVar13 = piVar13 + 2;
                iVar22 = iVar22 + -0x10;
              } while (0x10 < iVar22);
            }
LAB_0802cf08:
            *piVar13 = local_280;
            local_234 = local_234 + iVar22;
            piVar13[1] = iVar22;
            goto joined_r0x0802cf1c;
          }
        }
      }
    }
  }
  else {
    piVar13[1] = (int)local_29c;
    local_234 = local_234 + (int)local_29c;
    *piVar13 = (int)puVar16;
joined_r0x0802cf1c:
    local_238 = local_238 + 1;
    if (local_238 < 8) {
      piVar13 = piVar13 + 2;
      iVar20 = local_234;
    }
    else {
LAB_0802cf20:
      iVar20 = FUN_0802f8f4(param_1,param_2,&local_23c);
      if (iVar20 != 0) goto LAB_0802cef0;
      piVar13 = aiStack_200 + 2;
      iVar20 = local_234;
    }
  }
LAB_0802c912:
  iVar28 = DAT_0802d2f0;
  if (((uVar14 & 4) != 0) && (iVar22 = (int)local_2a8 - (int)local_2b8, 0 < iVar22)) {
    if (iVar22 < 0x11) {
      local_280 = DAT_0802e2b0;
    }
    else {
      local_280 = DAT_0802d2f0;
      local_234 = iVar20;
      do {
        while( true ) {
          iVar20 = iVar22;
          local_238 = local_238 + 1;
          local_234 = local_234 + 0x10;
          *piVar13 = iVar28;
          piVar13[1] = 0x10;
          if (local_238 < 8) break;
          iVar22 = FUN_0802f8f4(param_1,param_2,&local_23c);
          if (iVar22 != 0) goto LAB_0802cef0;
          piVar13 = aiStack_200 + 2;
          iVar22 = iVar20 + -0x10;
          if (iVar20 + -0x10 < 0x11) goto LAB_0802d1e0;
        }
        piVar13 = piVar13 + 2;
        iVar22 = iVar20 + -0x10;
      } while (0x10 < iVar20 + -0x10);
LAB_0802d1e0:
      iVar22 = iVar20 + -0x10;
      iVar20 = local_234;
    }
    local_238 = local_238 + 1;
    local_234 = iVar20 + iVar22;
    *piVar13 = local_280;
    piVar13[1] = iVar22;
    iVar20 = local_234;
    if ((7 < local_238) &&
       (iVar28 = FUN_0802f8f4(param_1,param_2,&local_23c), iVar20 = local_234, iVar28 != 0))
    goto LAB_0802cef0;
  }
  if ((int)local_2a8 < (int)local_2b8) {
    local_2a8 = local_2b8;
  }
  local_2ac = local_2ac + (int)local_2a8;
  if ((iVar20 == 0) || (iVar20 = FUN_0802f8f4(param_1,param_2), iVar20 == 0)) {
    local_238 = 0;
    if (local_2a0 != (uint *)0x0) {
      FUN_08028790(param_1,local_2a0);
    }
    piVar13 = aiStack_200 + 2;
    goto LAB_0802c6ae;
  }
LAB_0802cef0:
  if (local_2a0 != (uint *)0x0) {
    FUN_08028790(param_1,local_2a0);
  }
  goto LAB_0802c828;
switchD_0802c71e_caseD_31:
  uVar27 = uVar21 - 0x30;
  local_2a8 = (uint *)0x0;
  puVar29 = param_3;
  do {
    param_3 = puVar29 + 1;
    uVar21 = *puVar29;
    local_2a8 = (uint *)(uVar27 + (int)local_2a8 * 10);
    uVar27 = uVar21 - 0x30;
    puVar29 = param_3;
  } while (uVar27 < 10);
  goto LAB_0802c714;
code_r0x0802d792:
  if (puVar16 + uVar15 <= local_294) {
    local_294 = puVar16 + uVar15;
  }
  goto LAB_0802d272;
switchD_0802c71e_caseD_20:
  uVar21 = *param_3;
  if (local_260 == (uint *)0x0) {
    local_260 = (uint *)&Reserved2;
  }
  goto LAB_0802c712;
}

