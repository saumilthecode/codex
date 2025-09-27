
/* WARNING: Type propagation algorithm not settling */
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint * FUN_08007260(uint *param_1,int *param_2)

{
  byte bVar1;
  longlong lVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  undefined4 uVar5;
  int iVar6;
  uint *puVar7;
  undefined4 uVar8;
  byte *pbVar9;
  uint uVar10;
  uint uVar11;
  undefined4 extraout_r1;
  int extraout_r1_00;
  int extraout_r1_01;
  int extraout_r1_02;
  int extraout_r1_03;
  uint uVar12;
  byte *pbVar13;
  byte *pbVar14;
  byte *pbVar15;
  uint uVar16;
  int *piVar17;
  byte *pbVar18;
  byte *pbVar19;
  uint *puVar20;
  byte *unaff_r9;
  byte *pbVar21;
  uint unaff_r11;
  bool bVar22;
  undefined2 uStack_13c;
  ushort uStack_13a;
  undefined4 uStack_138;
  undefined4 uStack_134;
  undefined4 uStack_130;
  undefined4 uStack_12c;
  undefined4 uStack_128;
  uint *puStack_124;
  uint uStack_120;
  uint auStack_11c [4];
  int iStack_10c;
  int aiStack_108 [2];
  int iStack_100;
  char cStack_fc;
  char cStack_f4;
  byte bStack_f1;
  byte abStack_f0 [32];
  byte *pbStack_d0;
  byte *pbStack_cc;
  byte *pbStack_c8;
  int *piStack_c4;
  uint *puStack_c0;
  byte *pbStack_bc;
  byte *local_b0;
  byte *local_ac;
  byte *local_a4;
  byte *pbStack_a0;
  uint local_9c;
  uint local_98;
  uint local_94;
  uint local_90;
  uint local_8c;
  uint local_88;
  uint local_84;
  uint uStack_80;
  uint local_7c;
  uint local_78;
  uint uStack_74;
  uint local_70;
  uint uStack_6c;
  uint uStack_68;
  uint uStack_64;
  uint local_60;
  uint uStack_5c;
  uint local_58;
  uint local_54;
  uint uStack_50;
  uint local_4c;
  uint *local_48 [2];
  uint local_40 [4];
  uint uStack_30;
  uint uStack_2c;
  
  pbVar15 = (byte *)0x0;
  uVar12 = 0x30;
  local_9c = 0;
  local_98 = 0;
  local_94 = 0;
  local_90 = 0;
  local_8c = 0;
  FUN_08026922(&local_58,0);
  pbVar18 = (byte *)param_2[1];
  local_40[0] = local_40[0] & 0xffffff00;
  local_48[0] = local_40;
  if (pbVar18 == (byte *)0x0) {
    local_84 = local_54;
    uStack_80 = uStack_50;
    local_58 = 0xc;
    uStack_74 = uStack_2c;
    local_78 = uStack_30;
    local_7c = 0;
LAB_080073fc:
    local_70 = local_58;
    uStack_6c = local_84;
    uStack_68 = uStack_80;
    uStack_64 = local_7c;
    local_60 = local_78;
    uStack_5c = uStack_74;
    *param_1 = local_58;
    param_1[1] = local_84;
    param_1[2] = uStack_80;
    param_1[3] = local_7c;
    param_1[4] = local_78;
    param_1[5] = uStack_74;
    *(undefined1 *)(param_1 + 6) = 0;
LAB_08007424:
    local_88 = local_58;
    if (local_48[0] != local_40) {
      thunk_FUN_080249c4(local_48[0],local_40[0] + 1);
    }
    if (((local_8c & 0xff) != 0) && (local_98 != 0)) {
      thunk_FUN_080249c4(local_98,local_90 - local_98);
    }
    return param_1;
  }
  pbVar19 = pbVar18 + 0x10;
  if (pbVar19 <= pbVar18) {
    param_2[1] = (int)pbVar19;
    pbVar19[*param_2] = 0;
    goto LAB_080072a0;
  }
  if (0x7fffffffU - (int)pbVar18 < 0x10) {
LAB_080078ee:
    FUN_08010502(uRam080078fc);
    pbStack_d0 = pbVar15;
    pbStack_cc = pbVar18;
    pbStack_c8 = pbVar19;
    piStack_c4 = param_2;
    puStack_c0 = param_1;
    pbStack_bc = unaff_r9;
    FUN_080005d0();
    puVar3 = DAT_08007bf8;
    puVar7 = DAT_08007bf4;
    *(uint *)(DAT_08007bf0 + 0x40) = *(uint *)(DAT_08007bf0 + 0x40) | 0x10000000;
    *puVar7 = *puVar7 | 0x4000;
    uVar12 = *puVar7;
    puVar3[0x1e] = 2;
    puVar3[0x1f] = 0x2a;
    puVar3[0x19] = 1;
    puVar3[0x20] = 2;
    puVar3[0x21] = 7;
    puVar3[0x16] = 2;
    puVar3[0x1c] = 2;
    puVar3[0x1d] = 0;
    FUN_08001844(puVar3 + 0x16,uVar12 & 0x4000);
    puVar3[0x22] = 0xf;
    puVar3[0x23] = 2;
    puVar3[0x24] = 0;
    puVar3[0x25] = 0x1400;
    puVar3[0x26] = 0x1000;
    FUN_08001d30(puVar3 + 0x22,5);
    uVar12 = FUN_080006b0();
    if (0x1000 < uVar12) {
      *DAT_08007bfc = *DAT_08007bfc | 0x100;
    }
    uVar8 = DAT_08007c00;
    iVar6 = DAT_08007bf0;
    *(uint *)(DAT_08007bf0 + 0x30) = *(uint *)(DAT_08007bf0 + 0x30) | 1;
    *(uint *)(iVar6 + 0x44) = *(uint *)(iVar6 + 0x44) | 0x10;
    uStack_130 = 0;
    uStack_138 = 0x600;
    uStack_134 = 2;
    uStack_12c = 3;
    uStack_128 = 7;
    FUN_080011c0(uVar8,&uStack_138,*(uint *)(iVar6 + 0x44) & 0x10);
    uVar8 = DAT_08007c08;
    puVar3[4] = DAT_08007c04;
    puVar3[5] = 0x2580;
    puVar3[8] = 0;
    puVar3[9] = 0xc;
    puVar3[6] = 0;
    puVar3[7] = 0;
    puVar3[10] = 0;
    puVar3[0xb] = 0;
    FUN_08004328(uVar8);
    puVar4 = DAT_08007bf8;
    *(uint *)(iVar6 + 0x34) = *(uint *)(iVar6 + 0x34) | 0x40;
    uVar12 = *(uint *)(iVar6 + 0x34);
    *puVar3 = DAT_08007c0c;
    FUN_08001fa8(puVar4,extraout_r1,uVar12 & 0x40);
    uVar12 = *(uint *)(iVar6 + 0x40);
    puVar3[0x2a] = 0;
    *(uint *)(iVar6 + 0x40) = uVar12 | 0x8000;
    uVar5 = DAT_08007c14;
    uVar8 = DAT_08007c10;
    uVar12 = *(uint *)(iVar6 + 0x40);
    puVar3[0x2b] = 0;
    puVar3[0x28] = uVar8;
    puVar3[0x29] = 0x104;
    puVar3[0x2c] = 0;
    puVar3[0x2d] = 0;
    puVar3[0x2e] = 0x200;
    puVar3[0x2f] = 0x18;
    puVar3[0x30] = 0;
    puVar3[0x31] = 0;
    puVar3[0x32] = 0;
    puVar3[0x33] = 7;
    FUN_080024b0(uVar5,uVar12 & 0x8000);
LAB_08007a58:
    do {
      uStack_120 = 0;
      auStack_11c[0] = auStack_11c[0] & 0xffffff00;
      puStack_124 = auStack_11c;
      while( true ) {
        FUN_08004974(DAT_08007c08,abStack_f0,1,0xffffffff);
        bVar1 = abStack_f0[0];
        uVar12 = uStack_120;
        uVar11 = (uint)abStack_f0[0];
        if (uVar11 == 10) break;
        uVar16 = uStack_120 + 1;
        uVar10 = auStack_11c[0];
        puVar7 = puStack_124;
        if (puStack_124 == auStack_11c) {
          if (uVar16 == 0x10) {
            puVar7 = (uint *)FUN_08008466(0x1f);
            uVar10 = 0x1e;
LAB_08007ae8:
            puVar20 = puStack_124;
            if (uVar12 == 1) {
              *(char *)puVar7 = (char)*puStack_124;
            }
            else {
              FUN_08028666(puVar7,puStack_124,uVar12);
            }
            goto LAB_08007ac0;
          }
        }
        else if (auStack_11c[0] < uVar16) {
          if ((int)uVar16 < 0) goto LAB_08007d5a;
          uVar10 = auStack_11c[0] * 2;
          if (uVar16 < auStack_11c[0] << 1) {
            if ((int)uVar10 < 0) goto LAB_08007ba0;
            iVar6 = uVar10 + 1;
          }
          else {
            iVar6 = uStack_120 + 2;
            uVar10 = uVar16;
            if (iVar6 < 0) {
LAB_08007ba0:
              FUN_080104ea();
              goto LAB_08007ba4;
            }
          }
          puVar7 = (uint *)FUN_08008466(iVar6);
          puVar20 = puStack_124;
          if (uVar12 != 0) goto LAB_08007ae8;
LAB_08007ac0:
          if (puVar20 != auStack_11c) {
            thunk_FUN_080249c4(puVar20,auStack_11c[0] + 1);
          }
        }
        auStack_11c[0] = uVar10;
        puStack_124 = puVar7;
        *(byte *)((int)puStack_124 + uVar12) = bVar1;
        *(undefined1 *)((int)puStack_124 + uVar16) = 0;
        uStack_120 = uVar16;
      }
      FUN_08007260(&iStack_10c,&puStack_124);
      iVar6 = iStack_10c;
      if (cStack_f4 == '\0') {
LAB_08007ba4:
        FUN_080178c4(DAT_08007c1c,DAT_08007c18,0x3b);
        piVar17 = *(int **)((int)DAT_08007c1c + *(int *)(*DAT_08007c1c + -0xc) + 0x7c);
        if (piVar17 == (int *)0x0) {
          FUN_080104f6();
LAB_08007d5a:
          FUN_08010502(DAT_08007d84);
LAB_08007d60:
          FUN_080104f6();
          iVar6 = extraout_r1_03;
LAB_08007d2e:
          do {
            do {
              do {
                FUN_08006cec(&puStack_124,iVar6);
                FUN_08000664(1);
                FUN_08007dc2();
                iVar6 = extraout_r1_01;
              } while (cStack_fc == '\0');
              iVar6 = iStack_100 - aiStack_108[0];
            } while (aiStack_108[0] == 0);
            thunk_FUN_080249c4();
            iVar6 = extraout_r1_02;
          } while( true );
        }
        if ((char)piVar17[7] == '\0') {
          FUN_0800b34a(piVar17);
          if (*(code **)(*piVar17 + 0x18) != DAT_08007d80) {
            uVar11 = (**(code **)(*piVar17 + 0x18))(piVar17,10);
          }
        }
        else {
          uVar11 = (uint)*(byte *)((int)piVar17 + 0x27);
        }
        FUN_08017740(DAT_08007c1c,uVar11);
        FUN_080176b6();
LAB_08007bd8:
        if (puStack_124 != auStack_11c) {
          thunk_FUN_080249c4(puStack_124,auStack_11c[0] + 1);
        }
        FUN_08000664(1);
        goto LAB_08007a58;
      }
      if (0xe < iStack_10c - 1U) {
        FUN_080178c4(DAT_08007d6c,DAT_08007d68,0xe);
        piVar17 = *(int **)((int)DAT_08007d6c + *(int *)(*DAT_08007d6c + -0xc) + 0x7c);
        if (piVar17 != (int *)0x0) {
          if ((char)piVar17[7] == '\0') {
            FUN_0800b34a(piVar17);
            uVar12 = 10;
            if (*(code **)(*piVar17 + 0x18) != DAT_08007d80) {
              uVar12 = (**(code **)(*piVar17 + 0x18))(piVar17,10);
            }
          }
          else {
            uVar12 = (uint)*(byte *)((int)piVar17 + 0x27);
          }
          FUN_08017740(DAT_08007d6c,uVar12);
          FUN_080176b6();
          if ((cStack_fc != '\0') && (aiStack_108[0] != 0)) {
            thunk_FUN_080249c4(aiStack_108[0],iStack_100 - aiStack_108[0]);
          }
          goto LAB_08007bd8;
        }
        FUN_080104f6();
        iVar6 = extraout_r1_00;
        goto LAB_08007d2e;
      }
      FUN_08026922(abStack_f0,0,0x20);
      uVar12 = iVar6 << 5;
      uStack_13a = (ushort)((uVar12 & 0xff) << 8) | (ushort)(uVar12 >> 8) & 0xff;
      uStack_13c = 3;
      FUN_080017dc(DAT_08007c00,0x8000,0);
      FUN_080025bc(DAT_08007c14,&uStack_13c,4,0xffffffff);
      FUN_08002bec(DAT_08007c14,abStack_f0,0x20,0xffffffff);
      FUN_080017dc(DAT_08007c00,0x8000,1);
      if (cStack_fc == '\0') {
        FUN_080178c4(DAT_08007d6c,DAT_08007d70,5);
        uVar8 = FUN_0801796c(DAT_08007d6c,iVar6);
        FUN_080178c4(uVar8,DAT_08007d74,0xc);
        pbVar15 = &bStack_f1;
        while( true ) {
          pbVar15 = pbVar15 + 1;
          FUN_0801796c(DAT_08007d6c,*pbVar15);
          if (pbVar15 == abStack_f0 + 0x1f) break;
          FUN_080178c4(DAT_08007d6c,DAT_08007d78,1);
        }
        FUN_080178c4(DAT_08007d6c,DAT_08007d7c,1);
        piVar17 = *(int **)((int)DAT_08007d6c + *(int *)(*DAT_08007d6c + -0xc) + 0x7c);
        if (piVar17 == (int *)0x0) goto LAB_08007d60;
        if ((char)piVar17[7] == '\0') {
          FUN_0800b34a(piVar17);
          uVar12 = 10;
          if (*(code **)(*piVar17 + 0x18) != DAT_08007d80) {
            uVar12 = (**(code **)(*piVar17 + 0x18))(piVar17,10);
          }
        }
        else {
          uVar12 = (uint)*(byte *)((int)piVar17 + 0x27);
        }
        FUN_08017740(DAT_08007d6c,uVar12);
        FUN_080176b6();
      }
      else {
        FUN_0800023c(abStack_f0,aiStack_108);
        if (aiStack_108[0] != 0) {
          thunk_FUN_080249c4(aiStack_108[0],iStack_100 - aiStack_108[0]);
        }
      }
      if (puStack_124 != auStack_11c) {
        thunk_FUN_080249c4(puStack_124,auStack_11c[0] + 1);
      }
      FUN_08000664(1);
    } while( true );
  }
  unaff_r9 = (byte *)(param_2 + 2);
  pbVar15 = (byte *)*param_2;
  pbVar13 = pbVar19;
  if (pbVar15 == unaff_r9) {
    if (pbVar19 < (byte *)0x1e) {
      pbVar9 = (byte *)0x1f;
      pbVar13 = (byte *)0x1e;
      goto LAB_08007830;
    }
    pbVar15 = (byte *)FUN_08008466(pbVar18 + 0x11);
    pbVar9 = (byte *)*param_2;
LAB_080077ea:
    FUN_08028666(pbVar15,pbVar9,pbVar18);
LAB_08007844:
    if (unaff_r9 != pbVar9) {
      thunk_FUN_080249c4(pbVar9,param_2[2] + 1);
    }
    param_2[2] = (int)pbVar13;
    *param_2 = (int)pbVar15;
  }
  else {
    pbVar14 = (byte *)param_2[2];
    if (pbVar14 < pbVar19) {
      if ((int)pbVar19 < 0) {
        FUN_08010502(uRam080078f8);
        FUN_08006cec(local_48);
        if (((local_8c & 0xff) != 0) && (local_98 != 0)) {
          thunk_FUN_080249c4(local_98,local_90 - local_98);
        }
        FUN_08007dc2();
        goto LAB_080078ee;
      }
      pbVar21 = (byte *)((int)pbVar14 * 2);
      if (pbVar19 < (byte *)((int)pbVar14 << 1)) {
        if ((int)pbVar21 < 0) {
LAB_08007870:
          FUN_080104ea();
          goto LAB_08007878;
        }
        pbVar9 = pbVar21 + 1;
        pbVar13 = pbVar21;
      }
      else {
        pbVar9 = pbVar18 + 0x11;
        if ((int)pbVar9 < 0) goto LAB_08007870;
      }
LAB_08007830:
      pbVar15 = (byte *)FUN_08008466(pbVar9);
      pbVar9 = (byte *)*param_2;
      if (pbVar18 != (byte *)0x1) goto LAB_080077ea;
      *pbVar15 = *pbVar9;
      goto LAB_08007844;
    }
  }
  pbVar13 = pbVar15 + (int)pbVar18;
  pbVar13[0] = 0;
  pbVar13[1] = 0;
  pbVar13[2] = 0;
  pbVar13[3] = 0;
  pbVar15 = pbVar15 + (int)pbVar18;
  pbVar15[4] = 0;
  pbVar15[5] = 0;
  pbVar15[6] = 0;
  pbVar15[7] = 0;
  pbVar15[8] = 0;
  pbVar15[9] = 0;
  pbVar15[10] = 0;
  pbVar15[0xb] = 0;
  pbVar15[0xc] = 0;
  pbVar15[0xd] = 0;
  pbVar15[0xe] = 0;
  pbVar15[0xf] = 0;
  param_2[1] = (int)pbVar19;
  pbVar19[*param_2] = 0;
LAB_080072a0:
  unaff_r11 = local_58;
  local_ac = (byte *)*param_2;
  pbVar9 = (byte *)param_2[1];
  pbVar13 = pbVar9 + -0x10;
  pbVar21 = local_ac + (int)pbVar13;
  pbVar18 = local_ac;
  if (local_58 != 0) goto LAB_080077a0;
  uVar12 = (uint)*local_ac;
  bVar1 = DAT_08007450[uVar12];
  while (bVar1 != 0) {
    pbVar18 = pbVar18 + 1;
    uVar12 = (uint)*pbVar18;
    bVar1 = DAT_08007450[uVar12];
  }
  pbVar15 = DAT_08007450;
  pbVar19 = pbVar18;
  if (uVar12 != 0x7b) {
    local_58 = 0xf;
    goto LAB_080073c4;
  }
  uVar12 = (uint)pbVar18[1];
  local_b0 = pbVar18 + 1;
  pbVar14 = local_b0;
  if (DAT_08007450[uVar12] != 0) {
    do {
      pbVar13 = pbVar14;
      pbVar14 = pbVar13 + 1;
      uVar12 = (uint)*pbVar14;
    } while (DAT_08007450[uVar12] != 0);
    unaff_r11 = (int)pbVar13 - (int)pbVar18;
  }
  if (uVar12 == 0x7d) goto LAB_080077d2;
LAB_080072fc:
  pbVar18 = pbVar14;
  if (uVar12 != 0x22) goto LAB_080073ba;
LAB_08007300:
  pbVar18 = pbVar14 + 1;
  pbVar13 = pbVar14 + 6;
  if (pbVar14[1] == 0x73) {
    if (((pbVar13 < pbVar21) && (*(int *)(pbVar14 + 1) == s_slotH_0800774c._0_4_)) &&
       (pbVar14[5] == 0x22)) {
      uVar12 = (uint)pbVar14[6];
      bVar1 = pbVar15[uVar12];
      pbVar18 = pbVar13;
      while (bVar1 != 0) {
        pbVar18 = pbVar18 + 1;
        uVar12 = (uint)*pbVar18;
        bVar1 = pbVar15[uVar12];
      }
      if (uVar12 != 0x3a) goto LAB_080076d2;
      uVar12 = (uint)pbVar18[1];
      pbVar18 = pbVar18 + 1;
      bVar1 = pbVar15[uVar12];
      while (bVar1 != 0) {
        pbVar18 = pbVar18 + 1;
        uVar12 = (uint)*pbVar18;
        bVar1 = pbVar15[uVar12];
      }
      uVar11 = uVar12 - 0x30;
      if ((uVar11 & 0xff) < 10) {
        uVar10 = (uint)pbVar18[1];
        if ((uVar10 - 0x30 & 0xff) < 10) {
          local_9c = (uVar10 - 0x30) + uVar11 * 10;
          if (uVar12 == 0x30) goto LAB_080076ca;
          uVar10 = (uint)pbVar18[2];
          uVar12 = uVar10 - 0x30;
          if ((uVar12 & 0xff) < 10) {
            uVar10 = (uint)pbVar18[3];
            local_9c = uVar12 + local_9c * 10;
            uVar12 = uVar10 - 0x30;
            if ((uVar12 & 0xff) < 10) {
              uVar10 = (uint)pbVar18[4];
              local_9c = uVar12 + local_9c * 10;
              uVar12 = uVar10 - 0x30;
              if ((uVar12 & 0xff) < 10) {
                uVar10 = (uint)pbVar18[5];
                local_9c = uVar12 + local_9c * 10;
                uVar12 = uVar10 - 0x30;
                if ((uVar12 & 0xff) < 10) {
                  uVar10 = (uint)pbVar18[6];
                  local_9c = uVar12 + local_9c * 10;
                  uVar12 = uVar10 - 0x30;
                  if ((uVar12 & 0xff) < 10) {
                    uVar10 = (uint)pbVar18[7];
                    local_9c = uVar12 + local_9c * 10;
                    uVar12 = uVar10 - 0x30;
                    if ((uVar12 & 0xff) < 10) {
                      uVar10 = (uint)pbVar18[8];
                      local_9c = uVar12 + local_9c * 10;
                      uVar12 = uVar10 - 0x30;
                      if ((uVar12 & 0xff) < 10) {
                        uVar10 = (uint)pbVar18[9];
                        local_9c = uVar12 + local_9c * 10;
                        if ((uVar10 - 0x30 & 0xff) < 10) {
                          local_9c = (uVar10 - 0x30) + local_9c * 10;
                          if (uRam080078f4 < local_9c) {
                            uVar10 = (uint)pbVar18[10];
                            pbVar13 = pbVar18 + 10;
                            if (9 < uVar10 - 0x30) goto LAB_080076de;
                          }
                          goto LAB_080076ca;
                        }
                        pbVar13 = pbVar18 + 9;
                      }
                      else {
                        pbVar13 = pbVar18 + 8;
                      }
                    }
                    else {
                      pbVar13 = pbVar18 + 7;
                    }
                  }
                  else {
                    pbVar13 = pbVar18 + 6;
                  }
                }
                else {
                  pbVar13 = pbVar18 + 5;
                }
              }
              else {
                pbVar13 = pbVar18 + 4;
              }
            }
            else {
              pbVar13 = pbVar18 + 3;
            }
          }
          else {
            pbVar13 = pbVar18 + 2;
          }
        }
        else {
          pbVar13 = pbVar18 + 1;
          local_9c = uVar11;
        }
LAB_080076de:
        if ((uVar10 & 0xdf) == 0x45) {
          pbVar18 = pbVar13 + (pbVar13[1] == 0x2b) + 1;
          uVar12 = *pbVar18 - 0x30 & 0xff;
          if (uVar12 < 10) {
            uVar11 = pbVar18[1] - 0x30 & 0xff;
            if (uVar11 < 10) {
              uVar12 = uVar11 + uVar12 * 10 & 0xff;
              uVar11 = pbVar18[2] - 0x30 & 0xff;
              if (uVar11 < 10) {
                uVar12 = uVar11 + uVar12 * 10 & 0xff;
                pbVar13 = pbVar18 + 3;
              }
              else {
                pbVar13 = pbVar18 + 2;
              }
              pbVar18 = pbVar13;
              if (9 < uVar12) goto LAB_080076ca;
            }
            else {
              pbVar13 = pbVar18 + 1;
            }
            lVar2 = (ulonglong)*(uint *)(DAT_08007754 + uVar12 * 8) * (ulonglong)local_9c;
            uVar11 = (uint)lVar2;
            iVar6 = local_9c * *(int *)(DAT_08007754 + uVar12 * 8 + 4);
            pbVar18 = pbVar13;
            local_9c = uVar11;
            if (iVar6 + (int)((ulonglong)lVar2 >> 0x20) == 0) goto LAB_0800737e;
          }
        }
        else {
          pbVar18 = pbVar13;
          if (uVar10 != 0x2e) goto LAB_0800737e;
        }
      }
LAB_080076ca:
      pbVar9 = (byte *)param_2[1];
      local_58 = 0xe;
      goto LAB_080075f8;
    }
  }
  else if (((pbVar13 < pbVar21) && (*(int *)(pbVar14 + 1) == DAT_08007454)) && (pbVar14[5] == 0x22))
  {
    uVar12 = (uint)pbVar14[6];
    bVar1 = pbVar15[uVar12];
    pbVar18 = pbVar13;
    while (bVar1 != 0) {
      pbVar18 = pbVar18 + 1;
      uVar12 = (uint)*pbVar18;
      bVar1 = pbVar15[uVar12];
    }
    if (uVar12 == 0x3a) {
      uVar12 = (uint)pbVar18[1];
      pbVar13 = pbVar18 + 1;
      bVar1 = pbVar15[uVar12];
      while (bVar1 != 0) {
        pbVar13 = pbVar13 + 1;
        uVar12 = (uint)*pbVar13;
        bVar1 = pbVar15[uVar12];
      }
      if (uVar12 == 0x6e) goto LAB_0800760c;
      if ((local_8c & 0xff) == 0) {
        local_8c = CONCAT31(local_8c._1_3_,1);
        local_98 = 0;
        local_94 = 0;
        local_90 = 0;
      }
      local_a4 = pbVar13;
      pbStack_a0 = pbVar21;
      FUN_08006d04(&local_98,&local_58,&local_a4,&pbStack_a0);
      pbVar13 = local_a4;
      pbVar21 = pbStack_a0;
      goto LAB_08007378;
    }
LAB_080076d2:
    pbVar9 = (byte *)param_2[1];
    local_58 = 0x13;
    goto LAB_080075f8;
  }
  pbVar9 = (byte *)param_2[1];
  local_58 = 0x25;
LAB_080075f8:
  pbVar13 = pbVar9 + -0x10;
  if (pbVar9 < pbVar13) {
    do {
      FUN_08010502(ram0x08007750);
LAB_0800760c:
      if ((*(short *)(pbVar13 + 1) != 0x6c75) || (pbVar13[3] != 0x6c)) {
        pbVar9 = (byte *)param_2[1];
        local_58 = 0x18;
        pbVar18 = pbVar13 + 1;
        goto LAB_080075f8;
      }
      pbVar13 = pbVar13 + 4;
      if (((char)local_8c == '\0') || (local_8c = local_8c & 0xffffff00, local_98 == 0)) {
LAB_0800737e:
        uVar12 = (uint)*pbVar13;
        bVar1 = pbVar15[uVar12];
        pbVar18 = pbVar13;
        while (bVar1 != 0) {
          pbVar18 = pbVar18 + 1;
          uVar12 = (uint)*pbVar18;
          bVar1 = pbVar15[uVar12];
        }
        if (uVar12 == 0x7d) goto LAB_080077d0;
        if (uVar12 == 0x2c) {
          pbVar14 = pbVar18 + 1;
          if ((unaff_r11 != 0) && (unaff_r11 < (uint)((int)pbVar21 - (int)pbVar14))) {
            uVar11 = 0;
            if (unaff_r11 < 8) {
              pbVar13 = local_b0;
              uVar12 = unaff_r11;
              if (3 < unaff_r11) {
                if (*(int *)(pbVar19 + 1) != *(int *)(pbVar18 + 1)) goto LAB_080073a4;
                pbVar14 = pbVar18 + 5;
                uVar11 = -(uint)(unaff_r11 < 4);
                pbVar13 = pbVar19 + 5;
                uVar12 = unaff_r11 - 4;
              }
              if ((uVar11 != 0 || uVar11 < (1 < uVar12)) && (*(short *)pbVar13 == *(short *)pbVar14)
                 ) {
                pbVar14 = pbVar14 + 2;
              }
            }
            else {
              uVar12 = unaff_r11;
              if (unaff_r11 != 8) {
                do {
                  if (*(int *)(pbVar19 + ((unaff_r11 + 1) - uVar12) + 4) != *(int *)(pbVar14 + 4) ||
                      *(int *)(pbVar19 + ((unaff_r11 + 1) - uVar12)) != *(int *)pbVar14)
                  goto LAB_080073a4;
                  bVar22 = uVar12 < 8;
                  uVar12 = uVar12 - 8;
                  uVar11 = uVar11 - bVar22;
                  pbVar14 = pbVar14 + 8;
                } while (uVar11 != 0 || uVar11 < (8 < uVar12));
              }
LAB_08007878:
              pbVar14 = pbVar14 + -(8 - uVar12);
            }
          }
LAB_080073a4:
          uVar12 = (uint)*pbVar14;
          if (pbVar15[uVar12] == 0) goto LAB_080072fc;
          do {
            pbVar14 = pbVar14 + 1;
          } while (pbVar15[*pbVar14] != 0);
          pbVar18 = pbVar14;
          if (*pbVar14 == 0x22) goto LAB_08007300;
LAB_080073ba:
          pbVar9 = (byte *)param_2[1];
          local_58 = 0x11;
          pbVar13 = pbVar9 + -0x10;
        }
        else {
          pbVar9 = (byte *)param_2[1];
          local_58 = 0x12;
          pbVar13 = pbVar9 + -0x10;
        }
      }
      else {
        thunk_FUN_080249c4(local_98,local_90 - local_98);
LAB_08007378:
        if (local_58 == 0) goto LAB_0800737e;
        pbVar9 = (byte *)param_2[1];
        pbVar18 = pbVar13;
LAB_080077a0:
        unaff_r11 = local_58;
        if (local_58 != 10) goto LAB_080075f8;
        if (local_4c == 0) {
          local_58 = local_4c;
        }
        pbVar13 = pbVar9 + -0x10;
      }
LAB_080073c4:
      if (pbVar13 <= pbVar9) break;
    } while( true );
  }
  param_2[1] = (int)pbVar13;
  local_7c = (int)pbVar18 - (int)local_ac;
  pbVar13[*param_2] = 0;
  local_84 = local_54;
  uStack_80 = uStack_50;
  local_78 = uStack_30;
  uStack_74 = uStack_2c;
  if (local_58 != 0) goto LAB_080073fc;
  *param_1 = local_9c;
  *(undefined1 *)(param_1 + 4) = 0;
  if ((local_8c & 0xff) != 0) {
    param_1[3] = local_90;
    param_1[1] = local_98;
    param_1[2] = local_94;
    local_90 = local_58;
    local_98 = local_58;
    *(undefined1 *)(param_1 + 4) = 1;
  }
  *(undefined1 *)(param_1 + 6) = 1;
  goto LAB_08007424;
LAB_080077d0:
  pbVar9 = (byte *)param_2[1];
  pbVar14 = pbVar18;
LAB_080077d2:
  pbVar18 = pbVar14 + 1;
  goto LAB_080075f8;
}

