
/* WARNING: Globals starting with '_' overlap smaller symbols at the same address */

uint * FUN_08006d04(uint *param_1,int *param_2,undefined4 *param_3,int *param_4)

{
  bool bVar1;
  char cVar2;
  longlong lVar3;
  undefined4 *puVar4;
  undefined4 *puVar5;
  undefined4 uVar6;
  uint *puVar7;
  uint *puVar8;
  int iVar9;
  byte bVar10;
  uint *puVar11;
  int iVar12;
  byte *pbVar13;
  uint uVar14;
  undefined4 extraout_r1;
  int extraout_r1_00;
  int extraout_r1_01;
  int extraout_r1_02;
  int extraout_r1_03;
  uint uVar15;
  undefined1 *puVar16;
  char *pcVar17;
  byte *pbVar18;
  uint uVar19;
  uint *puVar20;
  ushort *puVar21;
  byte *pbVar22;
  uint uVar23;
  int *piVar24;
  byte *pbVar25;
  byte *pbVar26;
  byte *pbVar27;
  uint *puVar28;
  byte *pbVar29;
  uint *puVar30;
  undefined4 uVar31;
  bool bVar32;
  undefined8 uVar33;
  undefined2 uStack_17c;
  ushort uStack_17a;
  undefined4 uStack_178;
  undefined4 uStack_174;
  undefined4 uStack_170;
  undefined4 uStack_16c;
  undefined4 uStack_168;
  uint *puStack_164;
  uint uStack_160;
  uint auStack_15c [4];
  int iStack_14c;
  int aiStack_148 [2];
  int iStack_140;
  char cStack_13c;
  char cStack_134;
  byte bStack_131;
  byte abStack_130 [32];
  uint *puStack_110;
  byte *pbStack_10c;
  byte *pbStack_108;
  int *piStack_104;
  uint *puStack_100;
  uint *puStack_fc;
  int *piStack_f8;
  undefined4 uStack_f4;
  byte *pbStack_f0;
  byte *pbStack_ec;
  byte *pbStack_e4;
  byte *pbStack_e0;
  uint uStack_dc;
  uint *puStack_d8;
  uint uStack_d4;
  uint *puStack_d0;
  uint uStack_cc;
  uint *puStack_c8;
  uint uStack_c4;
  uint uStack_c0;
  uint uStack_bc;
  uint uStack_b8;
  uint uStack_b4;
  uint *puStack_b0;
  uint uStack_ac;
  uint uStack_a8;
  uint uStack_a4;
  uint uStack_a0;
  uint uStack_9c;
  uint *puStack_98;
  uint uStack_94;
  uint uStack_90;
  uint *puStack_8c;
  uint *apuStack_88 [2];
  uint auStack_80 [4];
  uint uStack_70;
  uint uStack_6c;
  int iStack_64;
  int iStack_60;
  byte *pbStack_5c;
  uint *puStack_58;
  int *piStack_54;
  uint *puStack_50;
  int *piStack_4c;
  uint *puStack_48;
  undefined4 uStack_44;
  uint *local_3c;
  uint *local_38;
  byte *local_34;
  uint *local_30;
  uint local_2c;
  
  iVar9 = DAT_08006f74;
  pbVar26 = (byte *)*param_3;
  uVar19 = (uint)*pbVar26;
  cVar2 = *(char *)(DAT_08006f74 + uVar19);
  while (cVar2 != '\0') {
    pbVar26 = pbVar26 + 1;
    *param_3 = pbVar26;
    uVar19 = (uint)*pbVar26;
    cVar2 = *(char *)(iVar9 + uVar19);
  }
  puVar7 = param_1;
  if (uVar19 != 0x5b) {
LAB_080071c0:
    *param_2 = 0x10;
    return puVar7;
  }
  local_3c = (uint *)(pbVar26 + 1);
  *param_3 = local_3c;
  uVar19 = (uint)pbVar26[1];
  cVar2 = *(char *)(iVar9 + uVar19);
  puVar20 = local_3c;
  while (cVar2 != '\0') {
    puVar20 = (uint *)((int)puVar20 + 1);
    *param_3 = puVar20;
    uVar19 = (uint)*(byte *)puVar20;
    cVar2 = *(char *)(iVar9 + uVar19);
  }
  puVar7 = (uint *)*param_1;
  puVar28 = (uint *)param_1[1];
  if (uVar19 == 0x5d) {
    *param_3 = (byte *)((int)puVar20 + 1);
    if (puVar28 != puVar7) {
LAB_0800717e:
      param_1[1] = (uint)puVar7;
      return puVar7;
    }
  }
  else {
    puVar30 = (uint *)((int)puVar20 - (int)local_3c);
    puVar8 = puVar7;
    puVar11 = local_3c;
    if (puVar28 != puVar7) {
      do {
        uVar15 = uVar19 - 0x30 & 0xff;
        puVar7 = (uint *)((int)puVar8 + 1);
        if (9 < uVar15) {
LAB_08006fec:
          *param_2 = 0xe;
          return puVar7;
        }
        *(byte *)puVar8 = (byte)(uVar19 - 0x30);
        uVar19 = *(byte *)((int)puVar20 + 1) - 0x30 & 0xff;
        if (uVar19 < 10) {
          uVar19 = uVar19 + uVar15 * 10;
          *(byte *)puVar8 = (byte)uVar19;
          if ((byte)*puVar20 == 0x30) goto LAB_08006fec;
          uVar15 = *(byte *)((int)puVar20 + 2) - 0x30 & 0xff;
          if (uVar15 < 10) {
            uVar15 = uVar15 + (uVar19 & 0xff) * 10;
            *(byte *)puVar8 = (byte)uVar15;
            if (((uVar15 & 0xff) < 0xf) ||
               (puVar21 = (ushort *)((int)puVar20 + 3), *(byte *)((int)puVar20 + 3) - 0x30 < 10))
            goto LAB_08006fec;
          }
          else {
            puVar21 = (ushort *)((int)puVar20 + 2);
          }
        }
        else {
          puVar21 = (ushort *)((int)puVar20 + 1);
        }
        *param_3 = puVar21;
        if (((byte)*puVar21 & 0xdf) == 0x45) {
          pbVar27 = (byte *)((int)puVar21 + 1);
          *param_3 = pbVar27;
          bVar32 = *(byte *)((int)puVar21 + 1) == 0x2b;
          pbVar25 = pbVar27 + bVar32;
          *param_3 = pbVar25;
          if (9 < pbVar27[bVar32] - 0x30) goto LAB_08006fec;
          *param_3 = pbVar25 + 1;
          uVar15 = pbVar25[1] - 0x30 & 0xff;
          uVar19 = pbVar27[bVar32] - 0x30 & 0xff;
          if (uVar15 < 10) {
            uVar19 = uVar15 + uVar19 * 10 & 0xff;
            *param_3 = pbVar25 + 2;
            uVar15 = pbVar25[2] - 0x30 & 0xff;
            if (uVar15 < 10) {
              *param_3 = pbVar25 + 3;
              uVar19 = uVar15 + uVar19 * 10 & 0xff;
            }
          }
          if ((2 < uVar19) ||
             (uVar19 = (int)(short)(ushort)(byte)*puVar8 *
                       (int)(short)(ushort)*(byte *)(iRam08007258 + uVar19),
             *(byte *)puVar8 = (byte)uVar19, 0xff < uVar19)) goto LAB_08006fec;
        }
        else if ((byte)*puVar21 == 0x2e) goto LAB_08006fec;
        if (*param_2 != 0) {
          return puVar7;
        }
        pbVar27 = (byte *)*param_3;
        uVar19 = (uint)*pbVar27;
        cVar2 = *(char *)(iVar9 + uVar19);
        while (cVar2 != '\0') {
          pbVar27 = pbVar27 + 1;
          *param_3 = pbVar27;
          uVar19 = (uint)*pbVar27;
          cVar2 = *(char *)(iVar9 + uVar19);
        }
        if (uVar19 != 0x2c) {
          if (uVar19 != 0x5d) goto LAB_080071c0;
          puVar20 = (uint *)param_1[1];
          *param_3 = pbVar27 + 1;
          if (puVar7 == puVar20) {
            return puVar7;
          }
          goto LAB_0800717e;
        }
        puVar20 = (uint *)(pbVar27 + 1);
        *param_3 = puVar20;
        if ((puVar30 != (uint *)0x0) && (puVar30 < (uint *)(*param_4 - (int)puVar20))) {
          if (puVar30 < &NMI) {
            if (puVar30 < &Reset) {
              puVar11 = local_3c;
              if ((uint *)0x1 < puVar30) {
LAB_08007052:
                if ((ushort)*puVar11 == (ushort)*puVar20) {
                  puVar20 = (uint *)((int)puVar20 + 2);
                  *param_3 = puVar20;
                }
              }
            }
            else if (*(int *)(pbVar26 + 1) == *(int *)(pbVar27 + 1)) {
              puVar20 = (uint *)(pbVar27 + 5);
              *param_3 = puVar20;
              puVar11 = (uint *)(pbVar26 + 5);
              if (-(uint)(puVar30 < &Reset) != 0 ||
                  -(uint)(puVar30 < &Reset) < (uint)((uint *)0x1 < puVar30 + -1)) goto LAB_08007052;
            }
          }
          else {
            if (puVar30 == (uint *)&NMI) {
              puVar11 = (uint *)&NMI;
            }
            else {
              uVar19 = 0;
              puVar11 = puVar30;
              do {
                local_38 = puVar30;
                local_30 = puVar7;
                if (*(uint *)((int)(pbVar26 + (int)puVar30 + (1 - (int)puVar11)) + 4) != puVar20[1]
                    || *(uint *)(pbVar26 + (int)puVar30 + (1 - (int)puVar11)) != *puVar20)
                goto LAB_08006e4e;
                bVar32 = puVar11 < &NMI;
                puVar11 = puVar11 + -2;
                uVar19 = uVar19 - bVar32;
                puVar20 = puVar20 + 2;
                *param_3 = puVar20;
              } while (uVar19 != 0 || uVar19 < (&NMI < puVar11));
            }
            puVar20 = (uint *)((int)puVar20 - (8 - (int)puVar11));
            *param_3 = puVar20;
          }
        }
LAB_08006e4e:
        uVar19 = (uint)(byte)*puVar20;
        cVar2 = *(char *)(iVar9 + uVar19);
        while (cVar2 != '\0') {
          puVar20 = (uint *)((int)puVar20 + 1);
          *param_3 = puVar20;
          uVar19 = (uint)*(byte *)puVar20;
          cVar2 = *(char *)(iVar9 + uVar19);
        }
        puVar8 = puVar7;
      } while (puVar7 != puVar28);
      puVar11 = (uint *)0x0;
    }
    if (puVar20 < (uint *)*param_4) {
      puVar16 = (undefined1 *)param_1[1];
      puVar20 = puVar30;
      local_34 = pbVar26;
      if (puVar16 == (undefined1 *)param_1[2]) goto LAB_080070a0;
LAB_08006e86:
      *puVar16 = 0;
      pbVar26 = (byte *)(param_1[1] + 1);
      param_1[1] = (uint)pbVar26;
      do {
        pcVar17 = (char *)*param_3;
        bVar10 = *pcVar17 - 0x30;
        if (9 < bVar10) goto LAB_08006fec;
        pbVar26[-1] = bVar10;
        if ((byte)(pcVar17[1] - 0x30U) < 10) {
          bVar10 = (pcVar17[1] - 0x30U) + bVar10 * '\n';
          pbVar26[-1] = bVar10;
          if (*pcVar17 == '0') goto LAB_08006fec;
          if ((byte)(pcVar17[2] - 0x30U) < 10) {
            bVar10 = (pcVar17[2] - 0x30U) + bVar10 * '\n';
            pbVar26[-1] = bVar10;
            if ((bVar10 < 0xf) || (pbVar27 = (byte *)(pcVar17 + 3), (byte)pcVar17[3] - 0x30 < 10))
            goto LAB_08006fec;
          }
          else {
            pbVar27 = (byte *)(pcVar17 + 2);
          }
        }
        else {
          pbVar27 = (byte *)(pcVar17 + 1);
        }
        *param_3 = pbVar27;
        puVar11 = (uint *)(*pbVar27 & 0xdf);
        if (puVar11 == (uint *)0x45) {
          puVar7 = (uint *)(pbVar27 + 1);
          *param_3 = puVar7;
          uVar19 = (uint)(pbVar27[1] == 0x2b);
          puVar11 = (uint *)((int)puVar7 + uVar19);
          *param_3 = puVar11;
          if (9 < *(byte *)((int)puVar7 + uVar19) - 0x30) goto LAB_08006fec;
          *param_3 = (byte *)((int)puVar11 + 1);
          uVar15 = *(byte *)((int)puVar11 + 1) - 0x30 & 0xff;
          uVar19 = *(byte *)((int)puVar7 + uVar19) - 0x30 & 0xff;
          if (uVar15 < 10) {
            uVar19 = uVar15 + uVar19 * 10 & 0xff;
            *param_3 = (ushort *)((int)puVar11 + 2);
            uVar15 = *(byte *)((int)puVar11 + 2) - 0x30 & 0xff;
            if (uVar15 < 10) {
              puVar11 = (uint *)((int)puVar11 + 3);
              *param_3 = puVar11;
              uVar19 = uVar15 + uVar19 * 10 & 0xff;
            }
          }
          if ((2 < uVar19) ||
             (uVar19 = (int)(short)(ushort)pbVar26[-1] *
                       (int)(short)(ushort)*(byte *)(iRam08007258 + uVar19),
             pbVar26[-1] = (byte)uVar19, 0xff < uVar19)) goto LAB_08006fec;
        }
        else if (*pbVar27 == 0x2e) goto LAB_08006fec;
        if (*param_2 != 0) {
          return puVar7;
        }
        puVar7 = (uint *)*param_3;
        uVar19 = (uint)(byte)*puVar7;
        cVar2 = *(char *)(iVar9 + uVar19);
        while (cVar2 != '\0') {
          puVar7 = (uint *)((int)puVar7 + 1);
          *param_3 = puVar7;
          uVar19 = (uint)*(byte *)puVar7;
          cVar2 = *(char *)(iVar9 + uVar19);
        }
        if (uVar19 != 0x2c) {
          if (uVar19 == 0x5d) {
            *param_3 = (byte *)((int)puVar7 + 1);
            return puVar7;
          }
          goto LAB_080071c0;
        }
        puVar21 = (ushort *)((int)puVar7 + 1);
        *param_3 = puVar21;
        if ((puVar30 != (uint *)0x0) && (puVar30 < (uint *)(*param_4 - (int)puVar21))) {
          puVar11 = (uint *)0x0;
          if (puVar30 < &NMI) {
            pbVar26 = (byte *)-(uint)((uint *)0x3 >= puVar30);
            puVar28 = local_3c;
            puVar8 = puVar30;
            if ((uint *)0x3 < puVar30) {
              puVar11 = *(uint **)(local_34 + 1);
              pbVar26 = local_34;
              if (puVar11 != *(uint **)((int)puVar7 + 1)) goto LAB_08007086;
              puVar21 = (ushort *)((int)puVar7 + 5);
              *param_3 = puVar21;
              puVar11 = (uint *)-(uint)(puVar30 < &Reset);
              puVar28 = (uint *)(local_34 + 5);
              puVar8 = puVar30 + -1;
            }
            bVar32 = puVar11 != (uint *)0x0;
            bVar1 = puVar11 < (uint *)(uint)((uint *)0x1 < puVar8);
            puVar11 = (uint *)((int)puVar11 - (uint)((uint *)0x1 >= puVar8));
            puVar7 = puVar28;
            if ((bVar32 || bVar1) &&
               (puVar11 = (uint *)(uint)(ushort)*puVar28, puVar11 == (uint *)(uint)*puVar21)) {
              puVar21 = puVar21 + 1;
              *param_3 = puVar21;
            }
          }
          else {
            puVar28 = puVar30;
            if (puVar30 != (uint *)&NMI) {
              puVar20 = (uint *)(local_34 + (int)puVar30 + 1);
              do {
                pbVar26 = *(byte **)puVar21;
                puVar7 = *(uint **)(puVar21 + 2);
                if ((uint *)((undefined4 *)((int)puVar20 - (int)puVar28))[1] != puVar7 ||
                    *(byte **)((int)puVar20 - (int)puVar28) != pbVar26) goto LAB_08007086;
                bVar32 = puVar28 < &NMI;
                puVar28 = puVar28 + -2;
                puVar11 = (uint *)((int)puVar11 - (uint)bVar32);
                puVar21 = puVar21 + 4;
                puVar7 = (uint *)((int)puVar11 - (uint)(&NMI >= puVar28));
                *param_3 = puVar21;
              } while (puVar11 != (uint *)0x0 || puVar11 < (uint *)(uint)(&NMI < puVar28));
            }
            puVar21 = (ushort *)((int)puVar21 - (8 - (int)puVar28));
            *param_3 = puVar21;
          }
        }
LAB_08007086:
        while (*(char *)(iVar9 + (uint)(byte)*puVar21) != '\0') {
          puVar21 = (ushort *)((int)puVar21 + 1);
          *param_3 = puVar21;
        }
        if ((ushort *)*param_4 <= puVar21) {
          return puVar7;
        }
        puVar16 = (undefined1 *)param_1[1];
        if (puVar16 != (undefined1 *)param_1[2]) goto LAB_08006e86;
LAB_080070a0:
        uVar19 = (int)puVar16 - (int)*param_1;
        if (uVar19 == 0x7fffffff) {
          uVar31 = 0x8007259;
          uVar33 = FUN_08010502(uRam0800725c,puVar11);
          piVar24 = (int *)((ulonglong)uVar33 >> 0x20);
          puVar11 = (uint *)((int)uVar33 * 0x20);
          iStack_60 = iVar9;
          iStack_64 = iVar9;
          puVar28 = (uint *)0x0;
          puVar7 = (uint *)&Reserved5;
          uStack_dc = 0;
          puStack_d8 = (uint *)0x0;
          uStack_d4 = 0;
          puStack_d0 = (uint *)0x0;
          uStack_cc = 0;
          pbStack_5c = pbVar26;
          puStack_58 = puVar30;
          piStack_54 = param_4;
          puStack_50 = param_1;
          piStack_4c = param_2;
          puStack_48 = puVar20;
          uStack_44 = uVar31;
          FUN_08026922(&puStack_98,0,0x30,0);
          pbVar26 = (byte *)piVar24[1];
          auStack_80[0] = auStack_80[0] & 0xffffff00;
          apuStack_88[0] = auStack_80;
          if (pbVar26 == (byte *)0x0) {
            uStack_c4 = uStack_94;
            uStack_c0 = uStack_90;
            puStack_98 = (uint *)&HardFault;
            uStack_b4 = uStack_6c;
            uStack_b8 = uStack_70;
            uStack_bc = 0;
LAB_080073fc:
            puStack_b0 = puStack_98;
            uStack_ac = uStack_c4;
            uStack_a8 = uStack_c0;
            uStack_a4 = uStack_bc;
            uStack_a0 = uStack_b8;
            uStack_9c = uStack_b4;
            *puVar11 = (uint)puStack_98;
            puVar11[1] = uStack_c4;
            puVar11[2] = uStack_c0;
            puVar11[3] = uStack_bc;
            puVar11[4] = uStack_b8;
            puVar11[5] = uStack_b4;
            *(undefined1 *)(puVar11 + 6) = 0;
LAB_08007424:
            puStack_c8 = puStack_98;
            if (apuStack_88[0] != auStack_80) {
              thunk_FUN_080249c4(apuStack_88[0],auStack_80[0] + 1);
            }
            if (((uStack_cc & 0xff) != 0) && (puStack_d8 != (uint *)0x0)) {
              thunk_FUN_080249c4(puStack_d8,(int)puStack_d0 - (int)puStack_d8);
            }
            return puVar11;
          }
          pbVar27 = pbVar26 + 0x10;
          if (pbVar26 < pbVar27) {
            if (0x7fffffffU - (int)pbVar26 < 0x10) {
LAB_080078ee:
              uVar31 = 0x80078f5;
              FUN_08010502(uRam080078fc);
              puStack_110 = puVar28;
              pbStack_10c = pbVar26;
              pbStack_108 = pbVar27;
              piStack_104 = piVar24;
              puStack_100 = puVar11;
              puStack_fc = param_1;
              piStack_f8 = param_2;
              uStack_f4 = uVar31;
              FUN_080005d0();
              puVar4 = DAT_08007bf8;
              puVar7 = DAT_08007bf4;
              *(uint *)(DAT_08007bf0 + 0x40) = *(uint *)(DAT_08007bf0 + 0x40) | 0x10000000;
              *puVar7 = *puVar7 | 0x4000;
              uVar19 = *puVar7;
              puVar4[0x1e] = 2;
              puVar4[0x1f] = 0x2a;
              puVar4[0x19] = 1;
              puVar4[0x20] = 2;
              puVar4[0x21] = 7;
              puVar4[0x16] = 2;
              puVar4[0x1c] = 2;
              puVar4[0x1d] = 0;
              FUN_08001844(puVar4 + 0x16,uVar19 & 0x4000);
              puVar4[0x22] = 0xf;
              puVar4[0x23] = 2;
              puVar4[0x24] = 0;
              puVar4[0x25] = 0x1400;
              puVar4[0x26] = 0x1000;
              FUN_08001d30(puVar4 + 0x22,5);
              uVar19 = FUN_080006b0();
              if (0x1000 < uVar19) {
                *DAT_08007bfc = *DAT_08007bfc | 0x100;
              }
              uVar31 = DAT_08007c00;
              iVar9 = DAT_08007bf0;
              *(uint *)(DAT_08007bf0 + 0x30) = *(uint *)(DAT_08007bf0 + 0x30) | 1;
              *(uint *)(iVar9 + 0x44) = *(uint *)(iVar9 + 0x44) | 0x10;
              uStack_170 = 0;
              uStack_178 = 0x600;
              uStack_174 = 2;
              uStack_16c = 3;
              uStack_168 = 7;
              FUN_080011c0(uVar31,&uStack_178,*(uint *)(iVar9 + 0x44) & 0x10);
              uVar31 = DAT_08007c08;
              puVar4[4] = DAT_08007c04;
              puVar4[5] = 0x2580;
              puVar4[8] = 0;
              puVar4[9] = 0xc;
              puVar4[6] = 0;
              puVar4[7] = 0;
              puVar4[10] = 0;
              puVar4[0xb] = 0;
              FUN_08004328(uVar31);
              puVar5 = DAT_08007bf8;
              *(uint *)(iVar9 + 0x34) = *(uint *)(iVar9 + 0x34) | 0x40;
              uVar19 = *(uint *)(iVar9 + 0x34);
              *puVar4 = DAT_08007c0c;
              FUN_08001fa8(puVar5,extraout_r1,uVar19 & 0x40);
              uVar19 = *(uint *)(iVar9 + 0x40);
              puVar4[0x2a] = 0;
              *(uint *)(iVar9 + 0x40) = uVar19 | 0x8000;
              uVar6 = DAT_08007c14;
              uVar31 = DAT_08007c10;
              uVar19 = *(uint *)(iVar9 + 0x40);
              puVar4[0x2b] = 0;
              puVar4[0x28] = uVar31;
              puVar4[0x29] = 0x104;
              puVar4[0x2c] = 0;
              puVar4[0x2d] = 0;
              puVar4[0x2e] = 0x200;
              puVar4[0x2f] = 0x18;
              puVar4[0x30] = 0;
              puVar4[0x31] = 0;
              puVar4[0x32] = 0;
              puVar4[0x33] = 7;
              FUN_080024b0(uVar6,uVar19 & 0x8000);
              goto LAB_08007a58;
            }
            param_1 = (uint *)(piVar24 + 2);
            puVar28 = (uint *)*piVar24;
            pbVar25 = pbVar27;
            if (puVar28 == param_1) {
              if (pbVar27 < (byte *)0x1e) {
                pbVar18 = (byte *)0x1f;
                pbVar25 = (byte *)0x1e;
                goto LAB_08007830;
              }
              puVar28 = (uint *)FUN_08008466(pbVar26 + 0x11);
              puVar7 = (uint *)*piVar24;
LAB_080077ea:
              FUN_08028666(puVar28,puVar7,pbVar26);
LAB_08007844:
              if (param_1 != puVar7) {
                thunk_FUN_080249c4(puVar7,piVar24[2] + 1);
              }
              piVar24[2] = (int)pbVar25;
              *piVar24 = (int)puVar28;
            }
            else {
              pbVar22 = (byte *)piVar24[2];
              if (pbVar22 < pbVar27) {
                if ((int)pbVar27 < 0) {
                  FUN_08010502(uRam080078f8);
                  FUN_08006cec(apuStack_88);
                  if (((uStack_cc & 0xff) != 0) && (puStack_d8 != (uint *)0x0)) {
                    thunk_FUN_080249c4(puStack_d8,(int)puStack_d0 - (int)puStack_d8);
                  }
                  FUN_08007dc2();
                  goto LAB_080078ee;
                }
                pbVar29 = (byte *)((int)pbVar22 * 2);
                if (pbVar27 < (byte *)((int)pbVar22 << 1)) {
                  if ((int)pbVar29 < 0) {
LAB_08007870:
                    FUN_080104ea();
                    pbVar26 = pbStack_ec;
                    goto LAB_08007878;
                  }
                  pbVar18 = pbVar29 + 1;
                  pbVar25 = pbVar29;
                }
                else {
                  pbVar18 = pbVar26 + 0x11;
                  if ((int)pbVar18 < 0) goto LAB_08007870;
                }
LAB_08007830:
                puVar28 = (uint *)FUN_08008466(pbVar18);
                puVar7 = (uint *)*piVar24;
                if (pbVar26 != (byte *)0x1) goto LAB_080077ea;
                *(byte *)puVar28 = (byte)*puVar7;
                goto LAB_08007844;
              }
            }
            pbVar25 = (byte *)((int)puVar28 + (int)pbVar26);
            pbVar25[0] = 0;
            pbVar25[1] = 0;
            pbVar25[2] = 0;
            pbVar25[3] = 0;
            puVar28 = (uint *)((int)puVar28 + (int)pbVar26);
            puVar28[1] = 0;
            puVar28[2] = 0;
            puVar28[3] = 0;
            piVar24[1] = (int)pbVar27;
            pbVar27[*piVar24] = 0;
          }
          else {
            piVar24[1] = (int)pbVar27;
            pbVar27[*piVar24] = 0;
          }
          puVar20 = puStack_98;
          pbVar26 = (byte *)*piVar24;
          pbVar13 = (byte *)piVar24[1];
          pbVar18 = pbVar13 + -0x10;
          pbVar29 = pbVar26 + (int)pbVar18;
          pbVar25 = pbVar26;
          if (puStack_98 != (uint *)0x0) goto LAB_080077a0;
          uVar19 = (uint)*pbVar26;
          bVar10 = *(byte *)((int)DAT_08007450 + uVar19);
          while (bVar10 != 0) {
            pbVar25 = pbVar25 + 1;
            uVar19 = (uint)*pbVar25;
            bVar10 = *(byte *)((int)DAT_08007450 + uVar19);
          }
          puVar28 = DAT_08007450;
          pbVar27 = pbVar25;
          if (uVar19 != 0x7b) {
            puStack_98 = (uint *)0xf;
            goto LAB_080073c4;
          }
          uVar19 = (uint)pbVar25[1];
          pbStack_f0 = pbVar25 + 1;
          pbVar22 = pbStack_f0;
          if (*(byte *)((int)DAT_08007450 + uVar19) != 0) {
            do {
              pbVar18 = pbVar22;
              pbVar22 = pbVar18 + 1;
              uVar19 = (uint)*pbVar22;
            } while (*(byte *)((int)DAT_08007450 + uVar19) != 0);
            puVar20 = (uint *)(pbVar18 + -(int)pbVar25);
          }
          if (uVar19 == 0x7d) goto LAB_080077d2;
LAB_080072fc:
          pbVar25 = pbVar22;
          if (uVar19 != 0x22) goto LAB_080073ba;
LAB_08007300:
          pbVar25 = pbVar22 + 1;
          pbVar18 = pbVar22 + 6;
          if (pbVar22[1] == 0x73) {
            if (((pbVar18 < pbVar29) && (*(int *)(pbVar22 + 1) == s_slotH_0800774c._0_4_)) &&
               (pbVar22[5] == 0x22)) {
              uVar19 = (uint)pbVar22[6];
              bVar10 = *(byte *)((int)puVar28 + uVar19);
              pbVar25 = pbVar18;
              while (bVar10 != 0) {
                pbVar25 = pbVar25 + 1;
                uVar19 = (uint)*pbVar25;
                bVar10 = *(byte *)((int)puVar28 + uVar19);
              }
              if (uVar19 != 0x3a) goto LAB_080076d2;
              uVar19 = (uint)pbVar25[1];
              pbVar25 = pbVar25 + 1;
              bVar10 = *(byte *)((int)puVar28 + uVar19);
              while (bVar10 != 0) {
                pbVar25 = pbVar25 + 1;
                uVar19 = (uint)*pbVar25;
                bVar10 = *(byte *)((int)puVar28 + uVar19);
              }
              uVar15 = uVar19 - 0x30;
              if ((uVar15 & 0xff) < 10) {
                uVar14 = (uint)pbVar25[1];
                if ((uVar14 - 0x30 & 0xff) < 10) {
                  uStack_dc = (uVar14 - 0x30) + uVar15 * 10;
                  if (uVar19 == 0x30) goto LAB_080076ca;
                  uVar14 = (uint)pbVar25[2];
                  uVar19 = uVar14 - 0x30;
                  if ((uVar19 & 0xff) < 10) {
                    uVar14 = (uint)pbVar25[3];
                    uStack_dc = uVar19 + uStack_dc * 10;
                    uVar19 = uVar14 - 0x30;
                    if ((uVar19 & 0xff) < 10) {
                      uVar14 = (uint)pbVar25[4];
                      uStack_dc = uVar19 + uStack_dc * 10;
                      uVar19 = uVar14 - 0x30;
                      if ((uVar19 & 0xff) < 10) {
                        uVar14 = (uint)pbVar25[5];
                        uStack_dc = uVar19 + uStack_dc * 10;
                        uVar19 = uVar14 - 0x30;
                        if ((uVar19 & 0xff) < 10) {
                          uVar14 = (uint)pbVar25[6];
                          uStack_dc = uVar19 + uStack_dc * 10;
                          uVar19 = uVar14 - 0x30;
                          if ((uVar19 & 0xff) < 10) {
                            uVar14 = (uint)pbVar25[7];
                            uStack_dc = uVar19 + uStack_dc * 10;
                            uVar19 = uVar14 - 0x30;
                            if ((uVar19 & 0xff) < 10) {
                              uVar14 = (uint)pbVar25[8];
                              uStack_dc = uVar19 + uStack_dc * 10;
                              uVar19 = uVar14 - 0x30;
                              if ((uVar19 & 0xff) < 10) {
                                uVar14 = (uint)pbVar25[9];
                                uStack_dc = uVar19 + uStack_dc * 10;
                                if ((uVar14 - 0x30 & 0xff) < 10) {
                                  uStack_dc = (uVar14 - 0x30) + uStack_dc * 10;
                                  if (uRam080078f4 < uStack_dc) {
                                    uVar14 = (uint)pbVar25[10];
                                    pbVar18 = pbVar25 + 10;
                                    if (9 < uVar14 - 0x30) goto LAB_080076de;
                                  }
                                  goto LAB_080076ca;
                                }
                                pbVar18 = pbVar25 + 9;
                              }
                              else {
                                pbVar18 = pbVar25 + 8;
                              }
                            }
                            else {
                              pbVar18 = pbVar25 + 7;
                            }
                          }
                          else {
                            pbVar18 = pbVar25 + 6;
                          }
                        }
                        else {
                          pbVar18 = pbVar25 + 5;
                        }
                      }
                      else {
                        pbVar18 = pbVar25 + 4;
                      }
                    }
                    else {
                      pbVar18 = pbVar25 + 3;
                    }
                  }
                  else {
                    pbVar18 = pbVar25 + 2;
                  }
                }
                else {
                  pbVar18 = pbVar25 + 1;
                  uStack_dc = uVar15;
                }
LAB_080076de:
                if ((uVar14 & 0xdf) == 0x45) {
                  pbVar25 = pbVar18 + (pbVar18[1] == 0x2b) + 1;
                  uVar19 = *pbVar25 - 0x30 & 0xff;
                  if (uVar19 < 10) {
                    uVar15 = pbVar25[1] - 0x30 & 0xff;
                    if (uVar15 < 10) {
                      uVar19 = uVar15 + uVar19 * 10 & 0xff;
                      uVar15 = pbVar25[2] - 0x30 & 0xff;
                      if (uVar15 < 10) {
                        uVar19 = uVar15 + uVar19 * 10 & 0xff;
                        pbVar18 = pbVar25 + 3;
                      }
                      else {
                        pbVar18 = pbVar25 + 2;
                      }
                      pbVar25 = pbVar18;
                      if (9 < uVar19) goto LAB_080076ca;
                    }
                    else {
                      pbVar18 = pbVar25 + 1;
                    }
                    lVar3 = (ulonglong)*(uint *)(DAT_08007754 + uVar19 * 8) * (ulonglong)uStack_dc;
                    uVar15 = (uint)lVar3;
                    iVar9 = uStack_dc * *(int *)(DAT_08007754 + uVar19 * 8 + 4);
                    pbVar25 = pbVar18;
                    uStack_dc = uVar15;
                    if (iVar9 + (int)((ulonglong)lVar3 >> 0x20) == 0) goto LAB_0800737e;
                  }
                }
                else {
                  pbVar25 = pbVar18;
                  if (uVar14 != 0x2e) goto LAB_0800737e;
                }
              }
LAB_080076ca:
              pbVar13 = (byte *)piVar24[1];
              puStack_98 = (uint *)0xe;
              goto LAB_080075f8;
            }
          }
          else if (((pbVar18 < pbVar29) && (*(int *)(pbVar22 + 1) == DAT_08007454)) &&
                  (pbVar22[5] == 0x22)) {
            uVar19 = (uint)pbVar22[6];
            bVar10 = *(byte *)((int)puVar28 + uVar19);
            pbVar25 = pbVar18;
            while (bVar10 != 0) {
              pbVar25 = pbVar25 + 1;
              uVar19 = (uint)*pbVar25;
              bVar10 = *(byte *)((int)puVar28 + uVar19);
            }
            if (uVar19 == 0x3a) {
              uVar19 = (uint)pbVar25[1];
              pbVar18 = pbVar25 + 1;
              bVar10 = *(byte *)((int)puVar28 + uVar19);
              while (bVar10 != 0) {
                pbVar18 = pbVar18 + 1;
                uVar19 = (uint)*pbVar18;
                bVar10 = *(byte *)((int)puVar28 + uVar19);
              }
              if (uVar19 == 0x6e) goto LAB_0800760c;
              if ((uStack_cc & 0xff) == 0) {
                uStack_cc = CONCAT31(uStack_cc._1_3_,1);
                puStack_d8 = (uint *)0x0;
                uStack_d4 = 0;
                puStack_d0 = (uint *)0x0;
              }
              pbStack_e4 = pbVar18;
              pbStack_e0 = pbVar29;
              FUN_08006d04(&puStack_d8,&puStack_98,&pbStack_e4,&pbStack_e0);
              pbVar18 = pbStack_e4;
              pbVar29 = pbStack_e0;
              goto LAB_08007378;
            }
LAB_080076d2:
            pbVar13 = (byte *)piVar24[1];
            puStack_98 = (uint *)0x13;
            goto LAB_080075f8;
          }
          pbVar13 = (byte *)piVar24[1];
          puStack_98 = (uint *)0x25;
LAB_080075f8:
          pbVar18 = pbVar13 + -0x10;
          if (pbVar13 < pbVar18) {
            do {
              FUN_08010502(ram0x08007750);
LAB_0800760c:
              if ((*(short *)(pbVar18 + 1) != 0x6c75) || (pbVar18[3] != 0x6c)) {
                pbVar13 = (byte *)piVar24[1];
                puStack_98 = (uint *)&UsageFault;
                pbVar25 = pbVar18 + 1;
                goto LAB_080075f8;
              }
              pbVar18 = pbVar18 + 4;
              if (((char)uStack_cc == '\0') ||
                 (uStack_cc = uStack_cc & 0xffffff00, puStack_d8 == (uint *)0x0)) {
LAB_0800737e:
                uVar19 = (uint)*pbVar18;
                bVar10 = *(byte *)((int)puVar28 + uVar19);
                pbVar25 = pbVar18;
                while (bVar10 != 0) {
                  pbVar25 = pbVar25 + 1;
                  uVar19 = (uint)*pbVar25;
                  bVar10 = *(byte *)((int)puVar28 + uVar19);
                }
                if (uVar19 == 0x7d) goto LAB_080077d0;
                if (uVar19 == 0x2c) {
                  pbVar22 = pbVar25 + 1;
                  if ((puVar20 != (uint *)0x0) && (puVar20 < pbVar29 + -(int)pbVar22)) {
                    uVar19 = 0;
                    if (puVar20 < &NMI) {
                      pbVar18 = pbStack_f0;
                      puVar7 = puVar20;
                      if ((uint *)0x3 < puVar20) {
                        if (*(int *)(pbVar27 + 1) != *(int *)(pbVar25 + 1)) goto LAB_080073a4;
                        pbVar22 = pbVar25 + 5;
                        uVar19 = -(uint)(puVar20 < &Reset);
                        pbVar18 = pbVar27 + 5;
                        puVar7 = puVar20 + -1;
                      }
                      if ((uVar19 != 0 || uVar19 < ((uint *)0x1 < puVar7)) &&
                         (*(short *)pbVar18 == *(short *)pbVar22)) {
                        pbVar22 = pbVar22 + 2;
                      }
                    }
                    else {
                      puVar7 = puVar20;
                      if (puVar20 != (uint *)&NMI) {
                        do {
                          pbStack_ec = pbVar26;
                          if (*(int *)(pbVar27 + (int)puVar20 + (1 - (int)puVar7) + 4) !=
                              *(int *)(pbVar22 + 4) ||
                              *(int *)(pbVar27 + (int)puVar20 + (1 - (int)puVar7)) !=
                              *(int *)pbVar22) goto LAB_080073a4;
                          bVar32 = puVar7 < &NMI;
                          puVar7 = puVar7 + -2;
                          uVar19 = uVar19 - bVar32;
                          pbVar22 = pbVar22 + 8;
                        } while (uVar19 != 0 || uVar19 < (&NMI < puVar7));
                      }
LAB_08007878:
                      pbVar22 = pbVar22 + -(8 - (int)puVar7);
                    }
                  }
LAB_080073a4:
                  uVar19 = (uint)*pbVar22;
                  if (*(byte *)((int)puVar28 + uVar19) == 0) goto LAB_080072fc;
                  do {
                    pbVar22 = pbVar22 + 1;
                  } while (*(byte *)((int)puVar28 + (uint)*pbVar22) != 0);
                  pbVar25 = pbVar22;
                  if (*pbVar22 == 0x22) goto LAB_08007300;
LAB_080073ba:
                  pbVar13 = (byte *)piVar24[1];
                  puStack_98 = (uint *)0x11;
                  pbVar18 = pbVar13 + -0x10;
                }
                else {
                  pbVar13 = (byte *)piVar24[1];
                  puStack_98 = (uint *)0x12;
                  pbVar18 = pbVar13 + -0x10;
                }
              }
              else {
                thunk_FUN_080249c4(puStack_d8,(int)puStack_d0 - (int)puStack_d8);
LAB_08007378:
                if (puStack_98 == (uint *)0x0) goto LAB_0800737e;
                pbVar13 = (byte *)piVar24[1];
                pbVar25 = pbVar18;
LAB_080077a0:
                puVar20 = puStack_98;
                if (puStack_98 != (uint *)0xa) goto LAB_080075f8;
                if (puStack_8c == (uint *)0x0) {
                  puStack_98 = puStack_8c;
                }
                pbVar18 = pbVar13 + -0x10;
              }
LAB_080073c4:
              if (pbVar18 <= pbVar13) break;
            } while( true );
          }
          piVar24[1] = (int)pbVar18;
          uStack_bc = (int)pbVar25 - (int)pbVar26;
          pbVar18[*piVar24] = 0;
          uStack_c4 = uStack_94;
          uStack_c0 = uStack_90;
          uStack_b8 = uStack_70;
          uStack_b4 = uStack_6c;
          if (puStack_98 != (uint *)0x0) goto LAB_080073fc;
          *puVar11 = uStack_dc;
          *(undefined1 *)(puVar11 + 4) = 0;
          if ((uStack_cc & 0xff) != 0) {
            puVar11[3] = (uint)puStack_d0;
            puVar11[1] = (uint)puStack_d8;
            puVar11[2] = uStack_d4;
            puStack_d0 = puStack_98;
            puStack_d8 = puStack_98;
            *(undefined1 *)(puVar11 + 4) = 1;
          }
          *(undefined1 *)(puVar11 + 6) = 1;
          goto LAB_08007424;
        }
        uVar15 = uVar19;
        if (uVar19 == 0) {
          uVar15 = 1;
        }
        if (CARRY4(uVar19,uVar15)) {
          local_38 = (uint *)0x7fffffff;
        }
        else {
          local_38 = (uint *)(uVar19 + uVar15);
          if ((uint *)0x7ffffffe < (uint *)(uVar19 + uVar15)) {
            local_38 = (uint *)0x7fffffff;
          }
        }
        local_30 = (uint *)*param_1;
        local_2c = uVar19;
        puVar20 = (uint *)FUN_08008466(local_38);
        *(byte *)((int)puVar20 + local_2c) = 0;
        pbVar26 = (byte *)(local_2c + 1 + (int)puVar20);
        if ((int)local_2c < 1) {
          puVar7 = puVar20;
          if (local_30 != (uint *)0x0) {
            iVar12 = param_1[2] - (int)local_30;
            goto LAB_08007210;
          }
        }
        else {
          FUN_08028666(puVar20,local_30);
          iVar12 = param_1[2] - (int)local_30;
LAB_08007210:
          puVar7 = (uint *)thunk_FUN_080249c4(local_30,iVar12);
        }
        *param_1 = (uint)puVar20;
        param_1[1] = (uint)pbVar26;
        param_1[2] = (uint)((int)local_38 + (int)puVar20);
      } while( true );
    }
  }
  return puVar7;
LAB_08007a58:
  uStack_160 = 0;
  auStack_15c[0] = auStack_15c[0] & 0xffffff00;
  puStack_164 = auStack_15c;
  while( true ) {
    FUN_08004974(DAT_08007c08,abStack_130,1,0xffffffff);
    bVar10 = abStack_130[0];
    uVar19 = uStack_160;
    uVar15 = (uint)abStack_130[0];
    if (uVar15 == 10) break;
    uVar23 = uStack_160 + 1;
    uVar14 = auStack_15c[0];
    puVar7 = puStack_164;
    if (puStack_164 == auStack_15c) {
      if (uVar23 == 0x10) {
        puVar7 = (uint *)FUN_08008466(0x1f);
        uVar14 = 0x1e;
LAB_08007ae8:
        puVar20 = puStack_164;
        if (uVar19 == 1) {
          *(char *)puVar7 = (char)*puStack_164;
        }
        else {
          FUN_08028666(puVar7,puStack_164,uVar19);
        }
        goto LAB_08007ac0;
      }
    }
    else if (auStack_15c[0] < uVar23) {
      if ((int)uVar23 < 0) goto LAB_08007d5a;
      uVar14 = auStack_15c[0] * 2;
      if (uVar23 < auStack_15c[0] << 1) {
        if ((int)uVar14 < 0) goto LAB_08007ba0;
        iVar9 = uVar14 + 1;
      }
      else {
        iVar9 = uStack_160 + 2;
        uVar14 = uVar23;
        if (iVar9 < 0) {
LAB_08007ba0:
          FUN_080104ea();
          goto LAB_08007ba4;
        }
      }
      puVar7 = (uint *)FUN_08008466(iVar9);
      puVar20 = puStack_164;
      if (uVar19 != 0) goto LAB_08007ae8;
LAB_08007ac0:
      if (puVar20 != auStack_15c) {
        thunk_FUN_080249c4(puVar20,auStack_15c[0] + 1);
      }
    }
    auStack_15c[0] = uVar14;
    puStack_164 = puVar7;
    *(byte *)((int)puStack_164 + uVar19) = bVar10;
    *(undefined1 *)((int)puStack_164 + uVar23) = 0;
    uStack_160 = uVar23;
  }
  FUN_08007260(&iStack_14c,&puStack_164);
  iVar9 = iStack_14c;
  if (cStack_134 == '\0') {
LAB_08007ba4:
    FUN_080178c4(DAT_08007c1c,DAT_08007c18,0x3b);
    piVar24 = *(int **)((int)DAT_08007c1c + *(int *)(*DAT_08007c1c + -0xc) + 0x7c);
    if (piVar24 == (int *)0x0) {
      FUN_080104f6();
LAB_08007d5a:
      FUN_08010502(DAT_08007d84);
LAB_08007d60:
      FUN_080104f6();
      iVar9 = extraout_r1_03;
LAB_08007d2e:
      do {
        do {
          do {
            FUN_08006cec(&puStack_164,iVar9);
            FUN_08000664(1);
            FUN_08007dc2();
            iVar9 = extraout_r1_01;
          } while (cStack_13c == '\0');
          iVar9 = iStack_140 - aiStack_148[0];
        } while (aiStack_148[0] == 0);
        thunk_FUN_080249c4();
        iVar9 = extraout_r1_02;
      } while( true );
    }
    if ((char)piVar24[7] == '\0') {
      FUN_0800b34a(piVar24);
      if (*(code **)(*piVar24 + 0x18) != DAT_08007d80) {
        uVar15 = (**(code **)(*piVar24 + 0x18))(piVar24,10);
      }
    }
    else {
      uVar15 = (uint)*(byte *)((int)piVar24 + 0x27);
    }
    FUN_08017740(DAT_08007c1c,uVar15);
    FUN_080176b6();
LAB_08007bd8:
    if (puStack_164 != auStack_15c) {
      thunk_FUN_080249c4(puStack_164,auStack_15c[0] + 1);
    }
    FUN_08000664(1);
    goto LAB_08007a58;
  }
  if (0xe < iStack_14c - 1U) {
    FUN_080178c4(DAT_08007d6c,DAT_08007d68,0xe);
    piVar24 = *(int **)((int)DAT_08007d6c + *(int *)(*DAT_08007d6c + -0xc) + 0x7c);
    if (piVar24 != (int *)0x0) {
      if ((char)piVar24[7] == '\0') {
        FUN_0800b34a(piVar24);
        uVar19 = 10;
        if (*(code **)(*piVar24 + 0x18) != DAT_08007d80) {
          uVar19 = (**(code **)(*piVar24 + 0x18))(piVar24,10);
        }
      }
      else {
        uVar19 = (uint)*(byte *)((int)piVar24 + 0x27);
      }
      FUN_08017740(DAT_08007d6c,uVar19);
      FUN_080176b6();
      if ((cStack_13c != '\0') && (aiStack_148[0] != 0)) {
        thunk_FUN_080249c4(aiStack_148[0],iStack_140 - aiStack_148[0]);
      }
      goto LAB_08007bd8;
    }
    FUN_080104f6();
    iVar9 = extraout_r1_00;
    goto LAB_08007d2e;
  }
  FUN_08026922(abStack_130,0,0x20);
  uVar19 = iVar9 << 5;
  uStack_17a = (ushort)((uVar19 & 0xff) << 8) | (ushort)(uVar19 >> 8) & 0xff;
  uStack_17c = 3;
  FUN_080017dc(DAT_08007c00,0x8000,0);
  FUN_080025bc(DAT_08007c14,&uStack_17c,4,0xffffffff);
  FUN_08002bec(DAT_08007c14,abStack_130,0x20,0xffffffff);
  FUN_080017dc(DAT_08007c00,0x8000,1);
  if (cStack_13c == '\0') {
    FUN_080178c4(DAT_08007d6c,DAT_08007d70,5);
    uVar31 = FUN_0801796c(DAT_08007d6c,iVar9);
    FUN_080178c4(uVar31,DAT_08007d74,0xc);
    pbVar26 = &bStack_131;
    while( true ) {
      pbVar26 = pbVar26 + 1;
      FUN_0801796c(DAT_08007d6c,*pbVar26);
      if (pbVar26 == abStack_130 + 0x1f) break;
      FUN_080178c4(DAT_08007d6c,DAT_08007d78,1);
    }
    FUN_080178c4(DAT_08007d6c,DAT_08007d7c,1);
    piVar24 = *(int **)((int)DAT_08007d6c + *(int *)(*DAT_08007d6c + -0xc) + 0x7c);
    if (piVar24 == (int *)0x0) goto LAB_08007d60;
    if ((char)piVar24[7] == '\0') {
      FUN_0800b34a(piVar24);
      uVar19 = 10;
      if (*(code **)(*piVar24 + 0x18) != DAT_08007d80) {
        uVar19 = (**(code **)(*piVar24 + 0x18))(piVar24,10);
      }
    }
    else {
      uVar19 = (uint)*(byte *)((int)piVar24 + 0x27);
    }
    FUN_08017740(DAT_08007d6c,uVar19);
    FUN_080176b6();
  }
  else {
    FUN_0800023c(abStack_130,aiStack_148);
    if (aiStack_148[0] != 0) {
      thunk_FUN_080249c4(aiStack_148[0],iStack_140 - aiStack_148[0]);
    }
  }
  if (puStack_164 != auStack_15c) {
    thunk_FUN_080249c4(puStack_164,auStack_15c[0] + 1);
  }
  FUN_08000664(1);
  goto LAB_08007a58;
LAB_080077d0:
  pbVar13 = (byte *)piVar24[1];
  pbVar22 = pbVar25;
LAB_080077d2:
  pbVar25 = pbVar22 + 1;
  goto LAB_080075f8;
}

