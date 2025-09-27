
uint FUN_080288f4(undefined4 param_1,int *param_2,int *param_3,int *param_4,int *param_5,
                 uint param_6)

{
  undefined1 *puVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  int extraout_r1;
  byte *pbVar7;
  int iVar8;
  uint uVar9;
  int *piVar10;
  int *piVar11;
  byte *pbVar12;
  byte *pbVar13;
  uint *puVar14;
  int iVar15;
  uint *puVar16;
  byte *pbVar17;
  byte *pbVar18;
  uint *puVar19;
  byte *pbVar20;
  uint uVar21;
  undefined8 uVar22;
  
  pbVar12 = (byte *)(*param_2 + 2);
  do {
    pbVar18 = pbVar12;
    pbVar12 = pbVar18 + 1;
  } while (*pbVar18 == 0x30);
  pbVar20 = pbVar18 + (-2 - *param_2);
  iVar3 = FUN_080288c8();
  if (iVar3 == 0) {
    iVar3 = FUN_08026936(pbVar18,DAT_08028ba4,1);
    pbVar17 = pbVar18;
    if ((iVar3 == 0) &&
       (iVar3 = FUN_080288c8(pbVar18[1]), pbVar7 = pbVar12, pbVar17 = pbVar12, iVar3 != 0)) {
      do {
        pbVar18 = pbVar7;
        pbVar7 = pbVar18 + 1;
      } while (*pbVar18 == 0x30);
      iVar3 = FUN_080288c8();
      pbVar13 = (byte *)(uint)(iVar3 == 0);
      pbVar20 = (byte *)0x1;
      pbVar7 = pbVar18;
      goto LAB_0802895e;
    }
    iVar3 = 0;
    pbVar13 = (byte *)0x1;
  }
  else {
    pbVar13 = (byte *)0x0;
    pbVar7 = pbVar18;
    pbVar12 = pbVar13;
LAB_0802895e:
    do {
      pbVar17 = pbVar7;
      pbVar7 = pbVar17 + 1;
      iVar3 = FUN_080288c8(*pbVar17);
    } while (iVar3 != 0);
    iVar3 = FUN_08026936(pbVar17,DAT_08028ba4,1);
    if (iVar3 == 0) {
      if (pbVar12 == (byte *)0x0) {
        pbVar12 = pbVar17 + 1;
        pbVar7 = pbVar12;
        do {
          pbVar17 = pbVar7;
          pbVar7 = pbVar17 + 1;
          iVar3 = FUN_080288c8(*pbVar17);
        } while (iVar3 != 0);
      }
    }
    else if (pbVar12 == (byte *)0x0) {
      iVar3 = 0;
      goto LAB_08028992;
    }
    iVar3 = ((int)pbVar12 - (int)pbVar17) * 4;
  }
LAB_08028992:
  pbVar12 = pbVar17;
  if ((*pbVar17 & 0xdf) == 0x50) {
    if (pbVar17[1] == 0x2b) {
      bVar2 = false;
LAB_08028a0c:
      pbVar7 = pbVar17 + 2;
    }
    else {
      if (pbVar17[1] == 0x2d) {
        bVar2 = true;
        goto LAB_08028a0c;
      }
      pbVar7 = pbVar17 + 1;
      bVar2 = false;
    }
    uVar22 = FUN_080288c8(*pbVar7);
    if (((int)uVar22 - 1U & 0xff) < 0x19) {
      while( true ) {
        iVar8 = (int)uVar22 + -0x10;
        puVar1 = (undefined1 *)((int)((ulonglong)uVar22 >> 0x20) + 1);
        uVar22 = FUN_080288c8(*puVar1,puVar1);
        pbVar12 = (byte *)((ulonglong)uVar22 >> 0x20);
        if (0x18 < ((int)uVar22 - 1U & 0xff)) break;
        uVar22 = CONCAT44(pbVar12,iVar8 * 10 + (int)uVar22);
      }
      if (bVar2) {
        iVar8 = -iVar8;
      }
      iVar3 = iVar3 + iVar8;
    }
  }
  *param_2 = (int)pbVar12;
  if (pbVar13 != (byte *)0x0) {
    if (pbVar20 != (byte *)0x0) {
      return 0;
    }
    return 6;
  }
  pbVar12 = pbVar17 + (-1 - (int)pbVar18);
  iVar8 = 0;
LAB_08028a26:
  if (7 < (int)pbVar12) {
LAB_08028a40:
    iVar8 = iVar8 + 1;
    pbVar12 = (byte *)((int)pbVar12 >> 1);
    goto LAB_08028a26;
  }
  iVar8 = FUN_08028f6c(param_1,iVar8);
  if (iVar8 == 0) {
    uVar6 = 0xe4;
    pbVar12 = DAT_08028ba8;
LAB_08028a3a:
    FUN_08028754(DAT_08028bac,uVar6,0);
    iVar8 = extraout_r1;
    goto LAB_08028a40;
  }
  puVar19 = (uint *)(iVar8 + 0x14);
  uVar9 = 0;
  uVar21 = 0;
  puVar14 = puVar19;
  while (pbVar18 < pbVar17) {
    pbVar17 = pbVar17 + -1;
    if (((*pbVar17 != 0x2e) || (pbVar17 < pbVar18)) ||
       (iVar4 = FUN_08026936(pbVar17,DAT_08028ba4,1), iVar4 != 0)) {
      puVar16 = puVar14;
      if (uVar9 == 0x20) {
        puVar16 = puVar14 + 1;
        *puVar14 = uVar21;
        uVar21 = 0;
        uVar9 = 0;
      }
      uVar5 = FUN_080288c8(*pbVar17);
      uVar21 = uVar21 | (uVar5 & 0xf) << (uVar9 & 0xff);
      uVar9 = uVar9 + 4;
      puVar14 = puVar16;
    }
  }
  *puVar14 = uVar21;
  iVar15 = (int)puVar14 + (4 - (int)puVar19) >> 2;
  *(int *)(iVar8 + 0x10) = iVar15;
  iVar4 = FUN_0802914c(uVar21);
  pbVar17 = (byte *)*param_3;
  iVar4 = iVar15 * 0x20 - iVar4;
  if ((int)pbVar17 < iVar4) {
    iVar4 = iVar4 - (int)pbVar17;
    uVar9 = FUN_08029886(iVar8,iVar4);
    if (uVar9 != 0) {
      uVar21 = iVar4 - 1;
      uVar9 = 1;
      if ((1 << (uVar21 & 0x1f) & puVar19[(int)uVar21 >> 5]) != 0) {
        if (((int)uVar21 < 2) || (iVar15 = FUN_08029886(iVar8,iVar4 + -2), iVar15 == 0)) {
          uVar9 = 2;
        }
        else {
          uVar9 = 3;
        }
      }
    }
    FUN_08028824(iVar8,iVar4);
    iVar3 = iVar3 + iVar4;
  }
  else {
    if (iVar4 < (int)pbVar17) {
      iVar8 = FUN_08029418(param_1,iVar8,(int)pbVar17 - iVar4);
      iVar3 = iVar3 - ((int)pbVar17 - iVar4);
      puVar19 = (uint *)(iVar8 + 0x14);
    }
    uVar9 = 0;
  }
  iVar4 = iVar8;
  if (param_3[2] < iVar3) goto LAB_08028ab2;
  if (iVar3 < param_3[1]) {
    pbVar12 = (byte *)(param_3[1] - iVar3);
    if ((int)pbVar17 <= (int)pbVar12) {
      iVar3 = param_3[3];
      if (iVar3 == 2) {
        if (param_6 != 0) goto LAB_08028b82;
      }
      else {
        if (iVar3 != 3) {
          if ((iVar3 != 1) || (pbVar17 != pbVar12)) goto LAB_08028b82;
          if (pbVar17 == (byte *)0x1) goto LAB_08028b5e;
          param_6 = FUN_08029886(iVar8,pbVar17 + -1);
        }
        if (param_6 == 0) {
LAB_08028b82:
          FUN_08028fe8(param_1,iVar8);
          *param_5 = 0;
          return 0x50;
        }
      }
LAB_08028b5e:
      *param_4 = param_3[1];
      *(undefined4 *)(iVar8 + 0x10) = 1;
      *puVar19 = 1;
      *param_5 = iVar8;
      return 0x62;
    }
    pbVar18 = pbVar12 + -1;
    if (uVar9 == 0) {
      if (pbVar18 != (byte *)0x0) {
        uVar9 = FUN_08029886(iVar8,pbVar18);
      }
    }
    else {
      uVar9 = 1;
    }
    if ((1 << ((uint)pbVar18 & 0x1f) & puVar19[(int)pbVar18 >> 5]) != 0) {
      uVar9 = uVar9 | 2;
    }
    FUN_08028824(iVar8,pbVar12);
    iVar3 = param_3[1];
    pbVar17 = pbVar17 + -(int)pbVar12;
    uVar21 = 2;
  }
  else {
    uVar21 = 1;
  }
  if (uVar9 == 0) goto LAB_08028c80;
  iVar15 = param_3[3];
  if (iVar15 != 2) {
    uVar5 = param_6;
    if (iVar15 == 3) goto joined_r0x08028c12;
    if ((iVar15 == 1) && ((uVar9 & 2) != 0)) {
      uVar5 = (uVar9 | *puVar19) & 1;
      goto joined_r0x08028c12;
    }
LAB_08028c14:
    uVar21 = uVar21 | 0x10;
    goto LAB_08028c80;
  }
  param_6 = 1 - param_6;
  uVar5 = param_6;
joined_r0x08028c12:
  if (uVar5 == 0) goto LAB_08028c14;
  iVar15 = *(int *)(iVar8 + 0x10);
  piVar10 = (int *)(iVar8 + 0x14);
  do {
    piVar11 = piVar10 + 1;
    if (*piVar10 != -1) {
      *piVar10 = *piVar10 + 1;
      goto LAB_08028c56;
    }
    *piVar10 = 0;
    piVar10 = piVar11;
  } while (piVar11 < (int *)(iVar8 + 0x14) + iVar15);
  if (*(int *)(iVar8 + 8) <= iVar15) {
    iVar4 = FUN_08028f6c(param_1,*(int *)(iVar8 + 4) + 1);
    if (iVar4 == 0) {
      uVar6 = 0x84;
      pbVar18 = (byte *)0x0;
      pbVar12 = DAT_08028d10;
      goto LAB_08028a3a;
    }
    FUN_08028666(iVar4 + 0xc,iVar8 + 0xc,(*(int *)(iVar8 + 0x10) + 2) * 4);
    FUN_08028fe8(param_1,iVar8);
  }
  iVar8 = *(int *)(iVar4 + 0x10);
  *(int *)(iVar4 + 0x10) = iVar8 + 1;
  *(undefined4 *)(iVar4 + iVar8 * 4 + 0x14) = 1;
LAB_08028c56:
  if (uVar21 == 2) {
    uVar21 = 2;
    if (((byte *)(*param_3 + -1) != pbVar17) ||
       ((1 << ((uint)pbVar17 & 0x1f) & *(uint *)(iVar4 + 0x14 + ((int)pbVar17 >> 5) * 4)) == 0))
    goto LAB_08028c7c;
  }
  else if ((iVar15 < *(int *)(iVar4 + 0x10)) ||
          ((((uint)pbVar17 & 0x1f) != 0 &&
           (iVar8 = FUN_0802914c(*(undefined4 *)(iVar4 + 0x14 + iVar15 * 4 + -4)),
           iVar8 < (int)(0x20 - ((uint)pbVar17 & 0x1f)))))) {
    FUN_08028824(iVar4,1);
    iVar3 = iVar3 + 1;
    if (param_3[2] < iVar3) {
LAB_08028ab2:
      FUN_08028fe8(param_1,iVar4);
      *param_5 = 0;
      return 0xa3;
    }
  }
  uVar21 = 1;
LAB_08028c7c:
  uVar21 = uVar21 | 0x20;
LAB_08028c80:
  *param_5 = iVar4;
  *param_4 = iVar3;
  return uVar21;
}

