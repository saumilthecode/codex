
void FUN_08027558(void)

{
  int *piVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  bool bVar4;
  undefined4 uVar5;
  int iVar6;
  char *pcVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  undefined1 uVar12;
  char *pcVar13;
  bool bVar14;
  ushort *puVar15;
  int *piVar16;
  ushort *puVar17;
  int *piVar18;
  ushort local_3c;
  ushort local_3a;
  ushort local_38;
  ushort local_36;
  ushort local_34;
  ushort local_32;
  int local_30;
  char *local_2c [2];
  
  uVar5 = *DAT_08027560;
  iVar6 = FUN_0802adc4();
  piVar1 = DAT_08027868;
  pcVar7 = (char *)FUN_08028f14(uVar5,DAT_08027864);
  uVar2 = DAT_08027870;
  iVar11 = *piVar1;
  if (pcVar7 == (char *)0x0) {
    *DAT_0802786c = 0;
    puVar3 = DAT_08027874;
    *(undefined4 *)(iVar6 + 0x28) = 0;
    *puVar3 = 0;
    puVar3 = DAT_08027878;
    *(undefined4 *)(iVar6 + 0x50) = 0;
    *puVar3 = uVar2;
    puVar3[1] = uVar2;
    *(undefined1 *)(iVar6 + 8) = 0x4a;
    *(undefined1 *)(iVar6 + 0x30) = 0x4a;
    *(undefined4 *)(iVar6 + 0xc) = 0;
    *(undefined4 *)(iVar6 + 0x10) = 0;
    *(undefined4 *)(iVar6 + 0x14) = 0;
    *(undefined4 *)(iVar6 + 0x18) = 0;
    *(undefined4 *)(iVar6 + 0x20) = 0;
    *(undefined4 *)(iVar6 + 0x24) = 0;
    *(undefined4 *)(iVar6 + 0x34) = 0;
    *(undefined4 *)(iVar6 + 0x38) = 0;
    *(undefined4 *)(iVar6 + 0x3c) = 0;
    *(undefined4 *)(iVar6 + 0x40) = 0;
    *(undefined4 *)(iVar6 + 0x48) = 0;
    *(undefined4 *)(iVar6 + 0x4c) = 0;
    FUN_080249c4(iVar11);
    *piVar1 = 0;
    return;
  }
  if ((iVar11 != 0) && (iVar11 = FUN_08005de4(), iVar11 == 0)) {
    return;
  }
  FUN_080249c4(*piVar1);
  iVar11 = FUN_08005ea0(pcVar7);
  iVar11 = FUN_08024a18(uVar5,iVar11 + 1);
  *piVar1 = iVar11;
  if (iVar11 != 0) {
    FUN_08028656(iVar11,pcVar7);
  }
  puVar3 = DAT_08027878;
  piVar1 = DAT_0802786c;
  *DAT_08027874 = 0;
  uVar2 = DAT_0802787c;
  *piVar1 = 0;
  *puVar3 = uVar2;
  puVar3[1] = uVar2;
  *(undefined4 *)(iVar6 + 0xc) = 0;
  *(undefined4 *)(iVar6 + 0x10) = 0;
  *(undefined4 *)(iVar6 + 0x14) = 0;
  *(undefined4 *)(iVar6 + 0x18) = 0;
  *(undefined4 *)(iVar6 + 0x20) = 0;
  *(undefined4 *)(iVar6 + 0x24) = 0;
  *(undefined4 *)(iVar6 + 0x34) = 0;
  *(undefined4 *)(iVar6 + 0x38) = 0;
  *(undefined4 *)(iVar6 + 0x3c) = 0;
  *(undefined4 *)(iVar6 + 0x40) = 0;
  *(undefined4 *)(iVar6 + 0x48) = 0;
  *(undefined4 *)(iVar6 + 0x4c) = 0;
  *(undefined1 *)(iVar6 + 8) = 0x4a;
  *(undefined4 *)(iVar6 + 0x28) = 0;
  *(undefined1 *)(iVar6 + 0x30) = 0x4a;
  *(undefined4 *)(iVar6 + 0x50) = 0;
  if (*pcVar7 == ':') {
    pcVar7 = pcVar7 + 1;
  }
  if (*pcVar7 == '<') {
    iVar11 = FUN_080262e4(pcVar7 + 1,DAT_08027884,DAT_08027880,&local_30);
    if (iVar11 < 1) {
      return;
    }
    if (7 < local_30 - 3U) {
      return;
    }
    if ((pcVar7 + 1)[local_30] != '>') {
      return;
    }
    pcVar7 = pcVar7 + 2;
  }
  else {
    iVar11 = FUN_080262e4(pcVar7,DAT_08027890,DAT_08027880,&local_30);
    if (iVar11 < 1) {
      return;
    }
    if (7 < local_30 - 3U) {
      return;
    }
  }
  pcVar13 = pcVar7 + local_30;
  if (pcVar7[local_30] == '-') {
    pcVar13 = pcVar13 + 1;
    iVar11 = -1;
  }
  else {
    if (pcVar7[local_30] == '+') {
      pcVar13 = pcVar13 + 1;
    }
    iVar11 = 1;
  }
  local_3a = 0;
  local_38 = 0;
  puVar15 = &local_3a;
  piVar16 = &local_30;
  puVar17 = &local_38;
  piVar18 = &local_30;
  iVar8 = FUN_080262e4(pcVar13,DAT_08027888,&local_3c,&local_30,puVar15,&local_30,&local_38,
                       &local_30);
  if (iVar8 < 1) {
    return;
  }
  iVar11 = iVar11 * ((uint)local_3c * 0xe10 + (uint)local_3a * 0x3c + (uint)local_38);
  pcVar7 = pcVar13 + local_30;
  if (pcVar13[local_30] == '<') {
    iVar8 = FUN_080262e4(pcVar7 + 1,DAT_08027884,DAT_0802788c,&local_30,puVar15,piVar16,puVar17,
                         piVar18);
    if ((0 < iVar8) || (pcVar7[1] != '>')) {
      if (7 < local_30 - 3U) {
        return;
      }
      if ((pcVar7 + 1)[local_30] != '>') {
        return;
      }
      pcVar7 = pcVar7 + 2;
LAB_0802773e:
      pcVar13 = pcVar7 + local_30;
      if (pcVar7[local_30] == '-') {
        pcVar13 = pcVar13 + 1;
        iVar8 = -1;
      }
      else {
        if (pcVar7[local_30] == '+') {
          pcVar13 = pcVar13 + 1;
        }
        iVar8 = 1;
      }
      local_3c = 0;
      local_3a = 0;
      local_38 = 0;
      local_30 = 0;
      iVar9 = FUN_080262e4(pcVar13,DAT_08027888,&local_3c,&local_30,&local_3a,&local_30,&local_38,
                           &local_30);
      if (iVar9 < 1) {
        iVar8 = iVar11 + -0xe10;
      }
      else {
        iVar8 = iVar8 * ((uint)local_3c * 0xe10 + (uint)local_3a * 0x3c + (uint)local_38);
      }
      pcVar13 = pcVar13 + local_30;
      iVar9 = iVar6;
      bVar4 = false;
      do {
        bVar14 = bVar4;
        if (*pcVar13 == ',') {
          pcVar13 = pcVar13 + 1;
        }
        if (*pcVar13 == 'M') {
          iVar10 = FUN_080262e4(pcVar13,DAT_08027894,&local_36,&local_30,&local_34,&local_30,
                                &local_32,&local_30);
          if (iVar10 != 3) {
            return;
          }
          if (0xb < local_36 - 1) {
            return;
          }
          if (4 < local_34 - 1) {
            return;
          }
          if (6 < local_32) {
            return;
          }
          *(uint *)(iVar9 + 0xc) = (uint)local_36;
          *(uint *)(iVar9 + 0x10) = (uint)local_34;
          *(undefined1 *)(iVar9 + 8) = 0x4d;
          *(uint *)(iVar9 + 0x14) = (uint)local_32;
          pcVar7 = pcVar13 + local_30;
        }
        else {
          if (*pcVar13 == 'J') {
            pcVar13 = pcVar13 + 1;
            uVar12 = 0x4a;
          }
          else {
            uVar12 = 0x44;
          }
          local_32 = FUN_08029a04(pcVar13,local_2c,10);
          pcVar7 = local_2c[0];
          if (local_2c[0] == pcVar13) {
            if (bVar14) {
              *(undefined1 *)(iVar6 + 0x30) = 0x4d;
              *(undefined4 *)(iVar6 + 0x34) = 0xb;
              *(undefined4 *)(iVar6 + 0x38) = 1;
              *(undefined4 *)(iVar6 + 0x3c) = 0;
            }
            else {
              *(undefined1 *)(iVar6 + 8) = 0x4d;
              *(undefined4 *)(iVar6 + 0xc) = 3;
              *(undefined4 *)(iVar6 + 0x10) = 2;
              *(undefined4 *)(iVar6 + 0x14) = 0;
            }
          }
          else {
            *(undefined1 *)(iVar9 + 8) = uVar12;
            *(uint *)(iVar9 + 0x14) = (uint)local_32;
          }
        }
        local_3c = 2;
        local_3a = 0;
        local_38 = 0;
        local_30 = 0;
        if (*pcVar7 == '/') {
          iVar10 = FUN_080262e4(pcVar7,DAT_08027898,&local_3c,&local_30,&local_3a,&local_30,
                                &local_38,&local_30);
          if (iVar10 < 1) {
            *(undefined4 *)(iVar6 + 0xc) = 0;
            *(undefined4 *)(iVar6 + 0x10) = 0;
            *(undefined4 *)(iVar6 + 0x14) = 0;
            *(undefined4 *)(iVar6 + 0x18) = 0;
            *(undefined4 *)(iVar6 + 0x20) = 0;
            *(undefined4 *)(iVar6 + 0x24) = 0;
            *(undefined4 *)(iVar6 + 0x34) = 0;
            *(undefined4 *)(iVar6 + 0x38) = 0;
            *(undefined4 *)(iVar6 + 0x3c) = 0;
            *(undefined4 *)(iVar6 + 0x40) = 0;
            *(undefined4 *)(iVar6 + 0x48) = 0;
            *(undefined4 *)(iVar6 + 0x4c) = 0;
            *(undefined1 *)(iVar6 + 8) = 0x4a;
            *(undefined4 *)(iVar6 + 0x28) = 0;
            *(undefined1 *)(iVar6 + 0x30) = 0x4a;
            *(undefined4 *)(iVar6 + 0x50) = 0;
            return;
          }
        }
        *(uint *)(iVar9 + 0x18) = (uint)local_3c * 0xe10 + (uint)local_3a * 0x3c + (uint)local_38;
        pcVar13 = pcVar7 + local_30;
        iVar9 = iVar9 + 0x28;
        bVar4 = true;
        if (bVar14) {
          *(int *)(iVar6 + 0x50) = iVar8;
          *puVar3 = DAT_080279a8;
          uVar2 = DAT_080279a0;
          uVar5 = *(undefined4 *)(iVar6 + 4);
          *(int *)(iVar6 + 0x28) = iVar11;
          puVar3[1] = uVar2;
          FUN_0802adcc(uVar5);
          iVar11 = *(int *)(iVar6 + 0x28);
          iVar6 = *(int *)(iVar6 + 0x50);
          *piVar1 = iVar11;
          iVar6 = iVar6 - iVar11;
          if (iVar6 != 0) {
            iVar6 = 1;
          }
          *DAT_080279ac = iVar6;
          return;
        }
      } while( true );
    }
  }
  else {
    iVar8 = FUN_080262e4(pcVar7,DAT_080279a4,DAT_080279a0,&local_30,puVar15,piVar16,puVar17,piVar18)
    ;
    if (0 < iVar8) {
      if (7 < local_30 - 3U) {
        return;
      }
      goto LAB_0802773e;
    }
  }
  uVar2 = DAT_08027880;
  *(int *)(iVar6 + 0x28) = iVar11;
  *puVar3 = uVar2;
  puVar3[1] = uVar2;
  *piVar1 = iVar11;
  return;
}

