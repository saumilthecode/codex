
uint FUN_0802e780(int param_1,int param_2)

{
  uint *puVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  uint *puVar6;
  uint uVar7;
  uint *puVar8;
  uint *puVar9;
  uint uVar10;
  uint *puVar11;
  uint *puVar12;
  
  iVar4 = *(int *)(param_2 + 0x10);
  if (iVar4 <= *(int *)(param_1 + 0x10)) {
    iVar5 = iVar4 + -1;
    puVar6 = (uint *)(param_2 + 0x14);
    puVar9 = (uint *)(param_1 + 0x14);
    puVar8 = puVar6 + iVar5;
    uVar7 = puVar9[iVar5] / (puVar6[iVar5] + 1);
    if (puVar6[iVar5] + 1 <= puVar9[iVar5]) {
      uVar2 = 0;
      iVar3 = 0;
      puVar1 = puVar9;
      puVar11 = puVar6;
      do {
        puVar12 = puVar11 + 1;
        uVar2 = uVar7 * (*puVar11 & 0xffff) + uVar2;
        uVar10 = uVar7 * (*puVar11 >> 0x10) + (uVar2 >> 0x10);
        uVar2 = ((*puVar1 & 0xffff) - (uVar2 & 0xffff)) + iVar3;
        iVar3 = (((int)uVar2 >> 0x10) - (uVar10 & 0xffff)) + (*puVar1 >> 0x10);
        *puVar1 = uVar2 & 0xffff | iVar3 * 0x10000;
        uVar2 = uVar10 >> 0x10;
        iVar3 = iVar3 >> 0x10;
        puVar1 = puVar1 + 1;
        puVar11 = puVar12;
      } while (puVar12 <= puVar8);
      if (puVar9[iVar5] == 0) {
        puVar1 = puVar9 + iVar4 + -2;
        while ((puVar9 < puVar1 && (*puVar1 == 0))) {
          iVar5 = iVar5 + -1;
          puVar1 = puVar1 + -1;
        }
        *(int *)(param_1 + 0x10) = iVar5;
      }
    }
    iVar4 = FUN_080294f4(param_1,param_2);
    if (-1 < iVar4) {
      iVar4 = 0;
      puVar1 = puVar9;
      do {
        puVar11 = puVar6 + 1;
        uVar2 = ((*puVar1 & 0xffff) - (*puVar6 & 0xffff)) + iVar4;
        iVar4 = (((int)uVar2 >> 0x10) - (*puVar6 >> 0x10)) + (*puVar1 >> 0x10);
        *puVar1 = uVar2 & 0xffff | iVar4 * 0x10000;
        iVar4 = iVar4 >> 0x10;
        puVar1 = puVar1 + 1;
        puVar6 = puVar11;
      } while (puVar11 <= puVar8);
      if (puVar9[iVar5] == 0) {
        puVar6 = puVar9 + iVar5 + -1;
        while ((puVar9 < puVar6 && (*puVar6 == 0))) {
          iVar5 = iVar5 + -1;
          puVar6 = puVar6 + -1;
        }
        *(int *)(param_1 + 0x10) = iVar5;
      }
      uVar7 = uVar7 + 1;
    }
    return uVar7;
  }
  return 0;
}

