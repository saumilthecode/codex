
/* WARNING: Type propagation algorithm not settling */

ulonglong FUN_08024b78(undefined4 *param_1,byte *param_2,undefined4 *param_3,undefined4 param_4)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  byte *pbVar4;
  undefined4 *puVar5;
  undefined4 extraout_r1;
  undefined4 uVar6;
  byte bVar7;
  int iVar8;
  byte *pbVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  int iVar14;
  int iVar15;
  uint uVar16;
  int iVar17;
  undefined4 uVar18;
  uint uVar19;
  uint uVar20;
  int iVar21;
  bool bVar22;
  bool bVar23;
  ulonglong uVar24;
  ulonglong uVar25;
  undefined8 uVar26;
  undefined8 uVar27;
  longlong lVar28;
  int local_84;
  int local_80;
  uint local_7c;
  undefined4 local_78;
  uint local_74;
  int local_6c;
  int local_60;
  byte *local_3c;
  int local_38;
  int local_34;
  uint local_30;
  uint local_2c;
  
  local_38 = 0;
  uVar24 = 0;
  pbVar4 = param_2;
LAB_08024b90:
  do {
    local_3c = pbVar4;
    bVar7 = *local_3c;
    if (bVar7 == 0x2b) {
      local_6c = 0;
LAB_08024bbe:
      pbVar4 = local_3c + 1;
      bVar7 = local_3c[1];
      if (bVar7 == 0) goto LAB_08024bca;
LAB_08024be2:
      local_3c = pbVar4;
      if (bVar7 != 0x30) {
        bVar22 = false;
        goto LAB_08024cb6;
      }
      if ((pbVar4[1] & 0xdf) != 0x58) goto LAB_08024ca4;
      uVar13 = FUN_080288f4(param_1,&local_3c,DAT_08024e00,&local_34,&local_38,local_6c,param_4);
      uVar13 = uVar13 & 0xf;
      uVar24 = 0;
      if (uVar13 != 0) {
        if (uVar13 == 6) {
          local_6c = 0;
          local_3c = pbVar4 + 1;
          uVar24 = 0;
        }
        else {
          if (local_38 != 0) {
            FUN_08029840(&local_30,0x35);
            FUN_08028fe8(param_1,local_38);
          }
          uVar19 = 0;
          uVar10 = 0;
          switch(uVar13) {
          case 1:
          case 5:
            uVar19 = local_30;
            uVar10 = local_2c & 0xffefffff | (local_34 + 0x433) * 0x100000;
            break;
          case 2:
            uVar19 = local_30;
            uVar10 = local_2c;
            break;
          case 3:
            uVar10 = DAT_08024e04;
            break;
          case 4:
            uVar19 = 0xffffffff;
            uVar10 = 0x7fffffff;
          }
          uVar24 = CONCAT44(uVar10,uVar19);
          if ((uVar10 & 0x7ff00000) == 0) {
            puVar5 = (undefined4 *)FUN_080285f8();
            *puVar5 = 0x22;
            uVar24 = CONCAT44(uVar10,uVar19);
          }
        }
      }
      goto LAB_08024c1c;
    }
    if (0x2b < bVar7) {
      if (bVar7 == 0x2d) {
        local_6c = 1;
        goto LAB_08024bbe;
      }
      local_6c = 0;
      pbVar4 = local_3c;
      goto LAB_08024be2;
    }
    pbVar4 = local_3c + 1;
    if (0xd < bVar7) {
      if (bVar7 != 0x20) goto LAB_08024baa;
      goto LAB_08024b90;
    }
  } while (8 < bVar7);
  if (bVar7 != 0) {
LAB_08024baa:
    local_6c = 0;
    bVar22 = false;
    goto LAB_08024cb6;
  }
  goto LAB_08024bca;
LAB_08024ca4:
  do {
    pbVar4 = pbVar4 + 1;
  } while (*pbVar4 == 0x30);
  local_3c = pbVar4;
  if (*pbVar4 == 0) goto LAB_08024c1c;
  bVar22 = true;
LAB_08024cb6:
  pbVar4 = local_3c;
  iVar17 = 0;
  local_60 = 0;
  iVar21 = 0;
  while( true ) {
    uVar13 = (uint)*local_3c;
    if (9 < uVar13 - 0x30) break;
    if (iVar21 < 9) {
      local_60 = local_60 * 10 + uVar13 + -0x30;
    }
    else {
      iVar17 = iVar17 * 10 + uVar13 + -0x30;
    }
    iVar21 = iVar21 + 1;
    local_3c = local_3c + 1;
  }
  iVar2 = FUN_08026936(local_3c,DAT_08024e08,1);
  iVar14 = iVar21;
  if (iVar2 == 0) {
    uVar13 = (uint)local_3c[1];
    if (iVar21 != 0) {
      iVar2 = 0;
      local_80 = 0;
      local_3c = local_3c + 1;
      goto LAB_08024d56;
    }
    iVar15 = 0;
    local_3c = local_3c + 1;
    while (uVar13 == 0x30) {
      iVar15 = iVar15 + 1;
      uVar13 = (uint)local_3c[1];
      local_3c = local_3c + 1;
    }
    if (uVar13 - 0x31 < 9) {
      iVar2 = 0;
      iVar14 = 0;
      pbVar4 = local_3c;
      local_80 = iVar15;
      do {
        iVar8 = uVar13 - 0x30;
        iVar15 = iVar2 + 1;
        iVar3 = iVar14;
        if (iVar8 != 0) {
          local_80 = local_80 + iVar2 + 1;
          iVar2 = iVar2 + iVar14;
          for (; iVar3 = iVar14 + 1, iVar14 != iVar2; iVar14 = iVar14 + 1) {
            if (iVar14 < 9) {
              local_60 = local_60 * 10;
            }
            else if (iVar3 < 0x11) {
              iVar17 = iVar17 * 10;
            }
          }
          if (iVar14 < 9) {
            local_60 = local_60 * 10 + iVar8;
          }
          else if (iVar14 < 0x10) {
            iVar17 = iVar17 * 10 + iVar8;
          }
          iVar15 = 0;
        }
        iVar2 = iVar15;
        uVar13 = (uint)local_3c[1];
        iVar14 = iVar3;
        local_3c = local_3c + 1;
LAB_08024d56:
      } while (uVar13 - 0x30 < 10);
      bVar23 = true;
      iVar15 = iVar2;
      goto LAB_08024ce4;
    }
    if ((uVar13 == 0x65) || (uVar13 == 0x45)) {
      local_80 = 0;
      bVar23 = true;
      goto LAB_08024cee;
    }
    bVar23 = true;
LAB_08024e64:
    uVar24 = 0;
    if (bVar22 || iVar15 != 0) goto LAB_08024c1c;
    if (bVar23) goto LAB_08024bca;
    if (uVar13 == 0x69) {
LAB_08024ecc:
      iVar21 = FUN_08028d38(&local_3c,DAT_0802510c);
      if (iVar21 == 0) goto LAB_08024bca;
      local_3c = local_3c + -1;
      iVar21 = FUN_08028d38(&local_3c,DAT_08025110);
      if (iVar21 == 0) {
        local_3c = local_3c + 1;
      }
      uVar24 = 0;
      goto LAB_08024c1c;
    }
    if (uVar13 < 0x6a) {
      if (uVar13 == 0x49) goto LAB_08024ecc;
      bVar22 = uVar13 == 0x4e;
    }
    else {
      bVar22 = uVar13 == 0x6e;
    }
    if ((bVar22) && (iVar21 = FUN_08028d38(&local_3c,DAT_08025104), iVar21 != 0)) {
      if ((*local_3c == 0x28) &&
         (iVar21 = FUN_08028d60(&local_3c,DAT_08025108,&local_30), iVar21 == 5)) {
        uVar24 = (ulonglong)local_30;
      }
      else {
        uVar24 = FUN_08028684(DAT_08025118);
      }
      goto LAB_08024c1c;
    }
LAB_08024bca:
    if (param_3 == (undefined4 *)0x0) {
      return 0;
    }
    local_6c = 0;
    local_3c = param_2;
    uVar24 = 0;
  }
  else {
    local_80 = 0;
    bVar23 = false;
    iVar15 = 0;
LAB_08024ce4:
    if ((uVar13 == 0x65) || (pbVar9 = local_3c, uVar13 == 0x45)) {
      if (iVar14 == 0) {
LAB_08024cee:
        if (!bVar22 && iVar15 == 0) goto LAB_08024bca;
        iVar14 = 0;
      }
      param_2 = local_3c;
      uVar13 = (uint)local_3c[1];
      if (uVar13 == 0x2b) {
        bVar1 = false;
LAB_08024df0:
        uVar13 = (uint)local_3c[2];
        local_3c = local_3c + 2;
      }
      else {
        if (uVar13 == 0x2d) {
          bVar1 = true;
          goto LAB_08024df0;
        }
        bVar1 = false;
        local_3c = local_3c + 1;
      }
      pbVar9 = param_2;
      if (9 < uVar13 - 0x30) goto LAB_08024d16;
      while (uVar13 == 0x30) {
        uVar13 = (uint)local_3c[1];
        local_3c = local_3c + 1;
      }
      pbVar9 = local_3c;
      if (8 < uVar13 - 0x31) goto LAB_08024d16;
      while( true ) {
        local_84 = uVar13 - 0x30;
        pbVar9 = pbVar9 + 1;
        uVar13 = (uint)*pbVar9;
        if (9 < uVar13 - 0x30) break;
        uVar13 = local_84 * 10 + uVar13;
      }
      if ((int)pbVar9 - (int)local_3c < 9) {
        if (0x4e1e < local_84) {
          local_84 = 19999;
        }
      }
      else {
        local_84 = 19999;
      }
      local_3c = pbVar9;
      if (bVar1) {
        local_84 = -local_84;
      }
    }
    else {
LAB_08024d16:
      local_3c = pbVar9;
      local_84 = 0;
    }
    if (iVar14 == 0) goto LAB_08024e64;
    uVar13 = local_84 - local_80;
    if (iVar21 == 0) {
      iVar21 = iVar14;
    }
    iVar2 = iVar14;
    if (0xf < iVar14) {
      iVar2 = 0x10;
    }
    uVar25 = FUN_08006134(local_60);
    if (iVar14 < 10) {
LAB_08024f2e:
      iVar17 = DAT_0802511c;
      uVar18 = (undefined4)(uVar25 >> 0x20);
      uVar24 = uVar25;
      if (uVar13 != 0) {
        if ((int)uVar13 < 1) {
          if ((int)(uVar13 + 0x16) < 0 != SCARRY4(uVar13,0x16)) goto LAB_08024f7e;
          puVar5 = (undefined4 *)(DAT_0802511c + (local_80 - local_84) * 8);
          uVar24 = FUN_0800647c((int)uVar25,uVar18,*puVar5,puVar5[1]);
        }
        else {
          if ((int)uVar13 < 0x17) {
            uVar27 = *(undefined8 *)(DAT_0802511c + uVar13 * 8);
          }
          else {
            if (0x25 - iVar14 < (int)uVar13) goto LAB_08024f7e;
            puVar5 = (undefined4 *)(DAT_0802511c + (0xf - iVar14) * 8);
            uVar27 = FUN_08006228(*puVar5,puVar5[1],(int)uVar25,uVar18);
            uVar25 = *(ulonglong *)(iVar17 + (uVar13 - (0xf - iVar14)) * 8);
          }
          uVar24 = FUN_08006228((int)uVar27,(int)((ulonglong)uVar27 >> 0x20),(int)uVar25,
                                (int)(uVar25 >> 0x20));
        }
      }
    }
    else {
      iVar15 = DAT_0802511c + iVar2 * 8;
      uVar27 = FUN_08006228((int)uVar25,(int)(uVar25 >> 0x20),*(undefined4 *)(iVar15 + -0x48),
                            *(undefined4 *)(iVar15 + -0x44));
      uVar26 = FUN_08006134(iVar17);
      uVar25 = FUN_08005ebc((int)uVar27,(int)((ulonglong)uVar27 >> 0x20),(int)uVar26,
                            (int)((ulonglong)uVar26 >> 0x20));
      if (iVar14 < 0x10) goto LAB_08024f2e;
LAB_08024f7e:
      uVar18 = (undefined4)(uVar25 >> 0x20);
      uVar19 = (iVar14 - iVar2) + uVar13;
      if ((int)uVar19 < 1) {
        if (uVar19 == 0) {
LAB_08025056:
          local_7c = 0;
LAB_0802519c:
          local_60 = FUN_080290b8(param_1,pbVar4,iVar21,iVar14,local_60);
          if (local_60 != 0) {
            iVar17 = local_80 - local_84;
            if (-1 < (int)uVar13) {
              iVar17 = 0;
            }
            iVar21 = 0;
            uVar19 = uVar13 & ~((int)uVar13 >> 0x1f);
            local_84 = 0;
LAB_080251ce:
            uVar10 = (uint)(uVar25 >> 0x20);
            uVar11 = (uint)uVar25;
            local_80 = FUN_08028f6c(param_1,*(undefined4 *)(local_60 + 4));
            if (local_80 == 0) goto LAB_08025064;
            FUN_08028666(local_80 + 0xc,local_60 + 0xc,(*(int *)(local_60 + 0x10) + 2) * 4);
            local_38 = FUN_08029730(param_1,extraout_r1,uVar11,uVar10,&local_34,&local_30);
            if (local_38 == 0) goto LAB_08025064;
            local_84 = FUN_080291e4(param_1,1);
            if (local_84 == 0) {
LAB_0802521e:
              local_84 = 0;
              goto LAB_08025064;
            }
            if (local_34 < 0) {
              uVar16 = uVar19 - local_34;
              iVar14 = iVar17;
            }
            else {
              uVar16 = uVar19;
              iVar14 = local_34 + iVar17;
            }
            iVar15 = (local_34 - local_7c) + local_30 + -1;
            iVar2 = 0x36 - local_30;
            if (iVar15 < DAT_08025318) {
              uVar12 = DAT_08025318 - iVar15;
              iVar2 = iVar2 - uVar12;
              if (0x1f < (int)uVar12) {
                uVar12 = 1 << (0xfffffbe2U - iVar15 & 0xff);
                goto LAB_080252f4;
              }
              uVar20 = 1 << (uVar12 & 0xff);
              uVar12 = 0;
            }
            else {
              uVar12 = 0;
LAB_080252f4:
              uVar20 = 1;
            }
            iVar15 = iVar14 + iVar2;
            iVar2 = uVar16 + iVar2 + local_7c;
            iVar3 = iVar14;
            if (iVar15 <= iVar14) {
              iVar3 = iVar15;
            }
            if (iVar2 <= iVar3) {
              iVar3 = iVar2;
            }
            if (0 < iVar3) {
              iVar15 = iVar15 - iVar3;
              iVar2 = iVar2 - iVar3;
              iVar14 = iVar14 - iVar3;
            }
            if (0 < iVar17) {
              local_84 = FUN_08029360(param_1,local_84,iVar17);
              if (local_84 == 0) goto LAB_0802521e;
              iVar3 = FUN_08029210(param_1,local_84,local_38);
              if (iVar3 == 0) goto LAB_08025064;
              FUN_08028fe8(param_1,local_38);
              local_38 = iVar3;
            }
            if ((0 < iVar15) && (local_38 = FUN_08029418(param_1,local_38,iVar15), local_38 == 0))
            goto LAB_08025064;
            if (((0 < (int)uVar13) &&
                (local_80 = FUN_08029360(param_1,local_80,uVar19), local_80 == 0)) ||
               ((0 < iVar2 && (local_80 = FUN_08029418(param_1,local_80,iVar2), local_80 == 0)))) {
              local_80 = 0;
              goto LAB_08025064;
            }
            if (((0 < iVar14) && (local_84 = FUN_08029418(param_1,local_84,iVar14), local_84 == 0))
               || (iVar21 = FUN_0802952c(param_1,local_38,local_80), iVar21 == 0))
            goto LAB_08025064;
            iVar2 = *(int *)(iVar21 + 0xc);
            *(undefined4 *)(iVar21 + 0xc) = 0;
            iVar14 = FUN_080294f4(iVar21,local_84);
            if (iVar14 < 0) {
              if ((((iVar2 == 0 && uVar11 == 0) && ((uVar25 & 0xfffff00000000) == 0)) &&
                  (0x6b00000 < (uVar10 & 0x7ff00000))) &&
                 ((*(int *)(iVar21 + 0x14) != 0 || (1 < *(int *)(iVar21 + 0x10))))) {
                iVar21 = FUN_08029418(param_1,iVar21,1);
                iVar17 = FUN_080294f4(iVar21,local_84);
                if (iVar17 < 1) goto LAB_08025430;
LAB_080253aa:
                uVar10 = DAT_08025648 & uVar10;
                if ((local_7c == 0) || (0x6b00000 < uVar10)) {
                  uVar25 = CONCAT44(~(~(uVar10 - 0x100000 >> 0x14) << 0x14),0xffffffff);
                  goto LAB_08025430;
                }
                if (uVar10 < 0x3700001) goto LAB_080250d8;
                goto LAB_080253c2;
              }
            }
            else {
              if (iVar14 != 0) {
                uVar27 = FUN_080297e0(iVar21,local_84);
                uVar6 = (undefined4)((ulonglong)uVar27 >> 0x20);
                uVar18 = (undefined4)uVar27;
                iVar14 = FUN_08006720(uVar18,uVar6,0,0x40000000);
                if (iVar14 == 0) {
                  lVar28 = FUN_08006228(uVar18,uVar6,0,DAT_0802565c);
                  local_74 = (uint)((ulonglong)lVar28 >> 0x20);
                  if (iVar2 == 0) {
LAB_080254fc:
                    local_74 = (int)((ulonglong)lVar28 >> 0x20) + 0x80000000;
                  }
                }
                else if (iVar2 == 0) {
                  if (uVar11 == 0) {
                    if ((uVar25 & 0xfffff00000000) == 0) {
                      iVar14 = FUN_0800670c(uVar18,uVar6,0,DAT_08025658);
                      if (iVar14 == 0) {
                        lVar28 = FUN_08006228(uVar18,uVar6,0,DAT_0802565c);
                      }
                      else {
                        lVar28 = (ulonglong)DAT_0802565c << 0x20;
                      }
                      goto LAB_080254fc;
                    }
                  }
                  else if (uVar25 == 1) goto LAB_080250d8;
                  lVar28 = (ulonglong)DAT_08025658 << 0x20;
                  local_74 = DAT_08025668;
                }
                else {
                  lVar28 = (ulonglong)DAT_08025658 << 0x20;
                  local_74 = DAT_08025658;
                }
                uVar18 = (undefined4)((ulonglong)lVar28 >> 0x20);
                local_78 = (undefined4)lVar28;
                uVar16 = DAT_08025648 & uVar10;
                if ((DAT_08025648 & uVar10) == DAT_08025660) {
                  uVar27 = FUN_0802965c(uVar11,uVar10 + 0xfcb00000);
                  uVar27 = FUN_08006228((int)uVar27,(int)((ulonglong)uVar27 >> 0x20),local_78,
                                        local_74);
                  uVar27 = FUN_08005ebc((int)uVar27,(int)((ulonglong)uVar27 >> 0x20),uVar11,
                                        uVar10 + 0xfcb00000);
                  uVar12 = (uint)((ulonglong)uVar27 >> 0x20);
                  if ((DAT_08025648 & uVar12) <= DAT_08025664) {
                    uVar25 = CONCAT44(uVar12 + 0x3500000,(int)uVar27);
                    goto LAB_080255d4;
                  }
                  if ((uVar10 == DAT_08025654) && (uVar11 == 0xffffffff)) goto LAB_08025064;
                  uVar25 = CONCAT44(DAT_08025654,0xffffffff);
                }
                else {
                  if ((local_7c != 0) && (uVar16 < 0x6a00001)) {
                    iVar14 = FUN_08006720(local_78,uVar18,DAT_08025710,DAT_08025714);
                    if (iVar14 != 0) {
                      iVar14 = FUN_08006788(local_78,uVar18);
                      if (iVar14 == 0) {
                        iVar14 = 1;
                      }
                      lVar28 = FUN_08006134(iVar14);
                      local_74 = (uint)((ulonglong)lVar28 >> 0x20);
                      if (iVar2 == 0) {
                        local_74 = local_74 + 0x80000000;
                      }
                    }
                    local_74 = (local_74 + 0x6b00000) - uVar16;
                  }
                  uVar27 = FUN_0802965c(uVar11,uVar10);
                  uVar27 = FUN_08006228((int)lVar28,local_74,(int)uVar27,
                                        (int)((ulonglong)uVar27 >> 0x20));
                  uVar25 = FUN_08005ebc((int)uVar27,(int)((ulonglong)uVar27 >> 0x20),uVar11,uVar10);
LAB_080255d4:
                  uVar18 = (undefined4)((ulonglong)lVar28 >> 0x20);
                  if ((local_7c == 0) && (uVar16 == ((uint)(uVar25 >> 0x20) & 0x7ff00000))) {
                    FUN_0802b340((int)lVar28,uVar18);
                    uVar27 = FUN_080061cc();
                    uVar27 = FUN_08005eb8((int)lVar28,uVar18,(int)uVar27,
                                          (int)((ulonglong)uVar27 >> 0x20));
                    uVar6 = (undefined4)((ulonglong)uVar27 >> 0x20);
                    uVar18 = (undefined4)uVar27;
                    if (((uVar25 & 0xfffff00000000) == 0 && (int)uVar25 == 0) && iVar2 == 0) {
                      iVar14 = FUN_0800670c(uVar18,uVar6,DAT_08025718,DAT_0802571c);
                    }
                    else {
                      iVar14 = FUN_0800670c(uVar18,uVar6,DAT_08025638,DAT_0802563c);
                      if (iVar14 != 0) goto LAB_0802507a;
                      iVar14 = FUN_08006748(uVar18,uVar6,DAT_08025640,DAT_08025644);
                    }
                    if (iVar14 != 0) goto LAB_0802507a;
                  }
                }
                FUN_08028fe8(param_1,local_38);
                FUN_08028fe8(param_1,local_80);
                FUN_08028fe8(param_1,local_84);
                FUN_08028fe8(param_1,iVar21);
                goto LAB_080251ce;
              }
              if (iVar2 == 0) {
                if ((uVar25 & 0xfffff00000000) == 0 && uVar11 == 0) goto LAB_080253aa;
              }
              else if ((uVar10 & 0xfffff) == DAT_08025650) {
                if (local_7c == 0) {
                  uVar13 = 0xffffffff;
                }
                else {
                  uVar13 = 0xffffffff;
                  if ((DAT_08025648 & uVar10) < 0x6a00001) {
                    uVar13 = -1 << (0x6b - ((DAT_08025648 & uVar10) >> 0x14) & 0xff);
                  }
                }
                if (uVar11 == uVar13) {
                  if ((uVar10 != DAT_08025654) || (uVar11 != 0xffffffff)) {
                    uVar25 = (ulonglong)((DAT_08025648 & uVar10) + 0x100000) << 0x20;
                    goto LAB_08025430;
                  }
                  goto LAB_08025064;
                }
              }
              if (uVar12 == 0) {
                uVar12 = uVar20 & uVar11;
              }
              else {
                uVar12 = uVar12 & uVar10;
              }
              if (uVar12 == 0) goto LAB_08025430;
              if (iVar2 == 0) {
                uVar27 = FUN_08024b30(uVar11,uVar10,local_7c);
                uVar25 = FUN_08005eb8(uVar11,uVar10,(int)uVar27,(int)((ulonglong)uVar27 >> 0x20));
                iVar17 = FUN_080066f8((int)uVar25,(int)(uVar25 >> 0x20),0,0);
                if (iVar17 != 0) goto LAB_080250d8;
              }
              else {
                uVar27 = FUN_08024b30(uVar11,uVar10,local_7c);
                uVar25 = FUN_08005ebc(uVar11,uVar10,(int)uVar27,(int)((ulonglong)uVar27 >> 0x20));
              }
            }
LAB_08025430:
            if (local_7c == 0) goto LAB_0802507a;
LAB_080253c2:
            uVar25 = FUN_08006228((int)uVar25,(int)(uVar25 >> 0x20),0,DAT_0802564c);
            if ((DAT_08025648 & (uint)(uVar25 >> 0x20)) == 0) {
              *param_1 = 0x22;
            }
            goto LAB_0802507a;
          }
          goto LAB_0802505c;
        }
        uVar10 = (int)-uVar19 >> 4;
        uVar19 = -uVar19 & 0xf;
        if ((uVar19 != 0) &&
           (puVar5 = (undefined4 *)(DAT_0802511c + uVar19 * 8),
           uVar25 = FUN_0800647c((int)uVar25,uVar18,*puVar5,puVar5[1]), uVar10 == 0))
        goto LAB_08025056;
        if ((int)uVar10 < 0x20) {
          local_7c = uVar10 & 0x10;
          if (local_7c != 0) {
            local_7c = 0x6a;
          }
          bVar22 = false;
          puVar5 = DAT_08025314;
          uVar24 = uVar25;
          do {
            if ((int)(uVar10 << 0x1f) < 0) {
              uVar24 = FUN_08006228((int)uVar24,(int)(uVar24 >> 0x20),*puVar5,puVar5[1]);
              bVar22 = true;
            }
            uVar10 = (int)uVar10 >> 1;
            puVar5 = puVar5 + 2;
          } while (uVar10 != 0);
          if (bVar22) {
            uVar25 = uVar24;
          }
          uVar19 = (uint)(uVar25 >> 0x20);
          if (local_7c != 0) {
            uVar10 = (uVar19 << 1) >> 0x15;
            iVar17 = -uVar10;
            uVar11 = iVar17 + 0x6b;
            if (0 < (int)uVar11) {
              if ((int)uVar11 < 0x20) {
                uVar25 = CONCAT44(uVar19,-1 << (uVar11 & 0xff) & (uint)uVar25);
              }
              else {
                bVar23 = SBORROW4(uVar11,0x34);
                bVar22 = uVar11 == 0x34;
                if ((int)uVar11 < 0x35) {
                  uVar11 = 0xffffffff;
                }
                if (bVar22 || iVar17 + 0x37 < 0 != bVar23) {
                  uVar25 = (ulonglong)(uVar11 << (0x4b - uVar10 & 0xff) & uVar19) << 0x20;
                }
                else {
                  uVar25 = 0x370000000000000;
                }
              }
            }
          }
          iVar17 = FUN_080066f8((int)uVar25,(int)(uVar25 >> 0x20),0,0);
          if (iVar17 != 0) goto LAB_080250d0;
          goto LAB_0802519c;
        }
LAB_080250d0:
        iVar21 = 0;
        local_84 = 0;
        local_60 = 0;
        local_80 = 0;
LAB_080250d8:
        *param_1 = 0x22;
      }
      else {
        if (((uVar19 & 0xf) != 0) &&
           (puVar5 = (undefined4 *)(DAT_0802511c + (uVar19 & 0xf) * 8),
           uVar25 = FUN_08006228(*puVar5,puVar5[1],(int)uVar25,uVar18), (uVar19 & 0xfffffff0) == 0))
        goto LAB_08025056;
        if ((int)(uVar19 & 0xfffffff0) < 0x135) {
          bVar22 = false;
          iVar17 = (int)uVar19 >> 4;
          iVar2 = 0;
          puVar5 = DAT_08025120;
          uVar24 = uVar25;
          while( true ) {
            if (iVar17 == 1) break;
            if (iVar17 << 0x1f < 0) {
              uVar24 = FUN_08006228((int)uVar24,(int)(uVar24 >> 0x20),*puVar5,puVar5[1]);
              bVar22 = true;
            }
            iVar2 = iVar2 + 1;
            iVar17 = iVar17 >> 1;
            puVar5 = puVar5 + 2;
          }
          if (bVar22) {
            uVar25 = uVar24;
          }
          uVar27 = FUN_08006228(DAT_08025120[iVar2 * 2],(DAT_08025120 + iVar2 * 2)[1],(int)uVar25,
                                (int)(uVar25 >> 0x20) + -0x3500000);
          uVar19 = (uint)((ulonglong)uVar27 >> 0x20);
          uVar10 = DAT_08025114 & uVar19;
          if (uVar10 <= DAT_08025124) {
            if (DAT_08025124 - 0x100000 < uVar10) {
              uVar25 = CONCAT44(DAT_08025128,0xffffffff);
            }
            else {
              uVar25 = CONCAT44(uVar19 + 0x3500000,(int)uVar27);
            }
            goto LAB_08025056;
          }
        }
LAB_0802505c:
        iVar21 = 0;
        local_84 = 0;
        local_60 = 0;
        local_80 = 0;
LAB_08025064:
        *param_1 = 0x22;
      }
      uVar25 = 0;
      uVar24 = 0;
      if (local_60 != 0) {
LAB_0802507a:
        FUN_08028fe8(param_1,local_38);
        FUN_08028fe8(param_1,local_80);
        FUN_08028fe8(param_1,local_84);
        FUN_08028fe8(param_1,local_60);
        FUN_08028fe8(param_1,iVar21);
        uVar24 = uVar25;
      }
    }
LAB_08024c1c:
    if (param_3 == (undefined4 *)0x0) goto LAB_08024c24;
  }
  *param_3 = local_3c;
LAB_08024c24:
  if (local_6c != 0) {
    uVar24 = uVar24 & 0xffffffff;
  }
  return uVar24;
}

