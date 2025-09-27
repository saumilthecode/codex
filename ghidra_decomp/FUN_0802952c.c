
int FUN_0802952c(undefined4 param_1,int param_2,int param_3,int param_4)

{
  int iVar1;
  int iVar2;
  undefined4 uVar3;
  uint uVar4;
  int *piVar5;
  uint uVar6;
  uint *puVar7;
  uint uVar8;
  uint *puVar9;
  uint *puVar10;
  int iVar11;
  uint *puVar12;
  int iVar13;
  uint *puVar14;
  int iVar15;
  uint *puVar16;
  uint *puVar17;
  bool bVar18;
  
  iVar1 = FUN_080294f4(param_2,param_3,param_3,param_4,param_1,param_2,param_3);
  bVar18 = iVar1 < 0;
  if (iVar1 == 0) {
    iVar2 = FUN_08028f6c(param_1,0);
    uVar8 = 0;
    iVar1 = iVar2;
    if (iVar2 != 0) goto LAB_0802955a;
    uVar3 = 0x237;
  }
  else {
    iVar1 = param_2;
    if (bVar18) {
      iVar1 = param_3;
      param_4 = param_2;
    }
    if (!bVar18) {
      param_4 = param_3;
    }
    uVar8 = (uint)bVar18;
    iVar2 = FUN_08028f6c(param_1,*(undefined4 *)(iVar1 + 4));
    if (iVar2 != 0) {
      iVar13 = *(int *)(iVar1 + 0x10);
      iVar11 = *(int *)(param_4 + 0x10);
      *(uint *)(iVar2 + 0xc) = uVar8;
      iVar15 = iVar1 + 0x14;
      puVar10 = (uint *)(iVar2 + 0x14);
      puVar7 = (uint *)(iVar1 + 0x10);
      puVar14 = (uint *)(iVar15 + iVar13 * 4);
      puVar12 = (uint *)(param_4 + 0x14) + iVar11;
      iVar1 = 0;
      puVar9 = puVar10;
      puVar16 = (uint *)(param_4 + 0x14);
      do {
        puVar17 = puVar16 + 1;
        puVar7 = puVar7 + 1;
        uVar8 = ((*puVar7 & 0xffff) - (*puVar16 & 0xffff)) + iVar1;
        iVar1 = ((*puVar7 >> 0x10) - (*puVar16 >> 0x10)) + ((int)uVar8 >> 0x10);
        *puVar9 = uVar8 & 0xffff | iVar1 * 0x10000;
        iVar1 = iVar1 >> 0x10;
        puVar9 = puVar9 + 1;
        puVar16 = puVar17;
      } while (puVar17 < puVar12);
      uVar8 = (int)puVar12 + (-0x15 - param_4) & 0xfffffffc;
      if (puVar12 < (uint *)(param_4 + 0x15)) {
        uVar8 = 0;
      }
      puVar9 = (uint *)(uVar8 + iVar15 + 4);
      for (puVar7 = puVar9; puVar7 < puVar14; puVar7 = puVar7 + 1) {
        uVar4 = *puVar7;
        uVar6 = uVar4 + iVar1;
        iVar11 = (uVar4 >> 0x10) + ((int)(iVar1 + (uVar4 & 0xffff)) >> 0x10);
        iVar1 = iVar11 >> 0x10;
        *(uint *)((int)puVar7 + ((int)puVar10 - iVar15)) = uVar6 & 0xffff | iVar11 * 0x10000;
      }
      uVar4 = (int)puVar14 + (3 - (int)puVar9) & 0xfffffffc;
      if (puVar14 < (uint *)(uVar8 + iVar15 + 1)) {
        uVar4 = 0;
      }
      piVar5 = (int *)((int)puVar10 + uVar4 + uVar8 + 4);
      while (piVar5 = piVar5 + -1, *piVar5 == 0) {
        iVar13 = iVar13 + -1;
      }
      *(int *)(iVar2 + 0x10) = iVar13;
      return iVar2;
    }
    uVar3 = 0x245;
    iVar1 = 0;
  }
  iVar2 = FUN_08028754(DAT_08029658,uVar3,iVar1,DAT_08029654);
LAB_0802955a:
  *(undefined4 *)(iVar2 + 0x10) = 1;
  *(uint *)(iVar2 + 0x14) = uVar8;
  return iVar1;
}

