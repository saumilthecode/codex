
void FUN_08029210(undefined4 param_1,int param_2,int param_3)

{
  ushort *puVar1;
  ushort *puVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  int iVar6;
  uint *puVar7;
  int iVar8;
  uint *puVar9;
  uint *puVar10;
  int iVar12;
  int iVar13;
  uint *puVar14;
  int iVar15;
  uint uVar16;
  uint uVar17;
  uint *puVar18;
  uint uVar19;
  uint *puVar11;
  
  iVar12 = *(int *)(param_2 + 0x10);
  iVar15 = *(int *)(param_3 + 0x10);
  iVar6 = param_3;
  iVar13 = iVar12;
  if (iVar15 <= iVar12) {
    iVar6 = param_2;
    param_2 = param_3;
    iVar13 = iVar15;
    iVar15 = iVar12;
  }
  iVar12 = *(int *)(iVar6 + 4);
  iVar8 = iVar15 + iVar13;
  if (*(int *)(iVar6 + 8) < iVar8) {
    iVar12 = iVar12 + 1;
  }
  iVar12 = FUN_08028f6c(param_1,iVar12);
  if (iVar12 == 0) {
    iVar12 = FUN_08028754(DAT_0802935c,0x162,0,DAT_08029358);
  }
  puVar7 = (uint *)(iVar12 + 0x14);
  puVar9 = puVar7 + iVar8;
  for (puVar5 = puVar7; puVar5 < puVar9; puVar5 = puVar5 + 1) {
    *puVar5 = 0;
  }
  puVar18 = (uint *)(iVar6 + 0x14);
  puVar1 = (ushort *)(param_2 + 0x14);
  puVar5 = puVar18 + iVar15;
  puVar2 = puVar1 + iVar13 * 2;
  uVar3 = (int)puVar5 + (-0x15 - iVar6) & 0xfffffffc;
  if (puVar5 < (uint *)(iVar6 + 0x15)) {
    uVar3 = 0;
  }
  while (puVar1 < puVar2) {
    uVar16 = (uint)*puVar1;
    if (uVar16 != 0) {
      uVar19 = 0;
      puVar10 = puVar18;
      puVar14 = puVar7;
      do {
        puVar11 = puVar10 + 1;
        uVar19 = uVar16 * (*puVar10 & 0xffff) + (*puVar14 & 0xffff) + uVar19;
        uVar4 = uVar16 * (*puVar10 >> 0x10) + (*puVar14 >> 0x10) + (uVar19 >> 0x10);
        *puVar14 = uVar19 & 0xffff | uVar4 * 0x10000;
        uVar19 = uVar4 >> 0x10;
        puVar10 = puVar11;
        puVar14 = puVar14 + 1;
      } while (puVar11 < puVar5);
      *(uint *)((int)puVar7 + uVar3 + 4) = uVar19;
    }
    uVar16 = (uint)puVar1[1];
    puVar1 = puVar1 + 2;
    if (uVar16 != 0) {
      uVar4 = *puVar7;
      uVar17 = 0;
      uVar19 = uVar4;
      puVar10 = puVar7;
      puVar14 = puVar18;
      do {
        uVar17 = uVar16 * (ushort)*puVar14 + uVar17 + (uVar19 >> 0x10);
        *puVar10 = uVar4 & 0xffff | uVar17 * 0x10000;
        puVar11 = puVar14 + 1;
        uVar19 = puVar10[1];
        uVar4 = uVar16 * (*puVar14 >> 0x10) + (uVar19 & 0xffff) + (uVar17 >> 0x10);
        uVar17 = uVar4 >> 0x10;
        puVar10 = puVar10 + 1;
        puVar14 = puVar11;
      } while (puVar11 < puVar5);
      *(uint *)((int)puVar7 + uVar3 + 4) = uVar4;
    }
    puVar7 = puVar7 + 1;
  }
  while ((0 < iVar8 && (puVar9 = puVar9 + -1, *puVar9 == 0))) {
    iVar8 = iVar8 + -1;
  }
  *(int *)(iVar12 + 0x10) = iVar8;
  return;
}

