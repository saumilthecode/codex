
undefined4 FUN_08028d60(int *param_1,uint *param_2,uint *param_3)

{
  byte bVar1;
  uint uVar2;
  undefined4 uVar3;
  int iVar4;
  uint *puVar5;
  uint uVar6;
  int iVar7;
  uint *puVar8;
  uint *puVar10;
  uint *puVar11;
  int iVar12;
  uint *puVar13;
  int iVar14;
  int local_38;
  uint *puVar9;
  
  iVar4 = *param_1;
  puVar10 = param_3 + ((int)*param_2 >> 5);
  uVar6 = *param_2 & 0x1f;
  if (uVar6 != 0) {
    puVar10 = puVar10 + 1;
  }
  iVar12 = 0;
  puVar13 = puVar10 + -1;
  puVar10[-1] = 0;
  local_38 = 0;
  iVar14 = 0;
  puVar11 = puVar13;
  puVar5 = puVar13;
LAB_08028d8e:
  while( true ) {
    bVar1 = *(byte *)(iVar4 + 1);
    iVar7 = iVar4 + 1;
    if (bVar1 == 0) break;
    uVar2 = FUN_080288c8(bVar1);
    if (uVar2 != 0) {
      iVar12 = iVar12 + 1;
      iVar14 = iVar14 + 1;
      if (8 < iVar12) goto code_r0x08028e56;
      goto LAB_08028e64;
    }
    if (0x20 < bVar1) {
      if (bVar1 != 0x29) goto LAB_08028e96;
      *param_1 = iVar4 + 2;
      break;
    }
    iVar4 = iVar7;
    if (local_38 < iVar14) {
      if ((puVar11 < puVar5) && (iVar12 < 8)) {
        FUN_08028d14(puVar11,puVar5,iVar12);
      }
      if (param_3 < puVar11) {
        puVar5 = puVar11 + -1;
        puVar11[-1] = 0;
        iVar12 = 0;
        puVar11 = puVar5;
        local_38 = iVar14;
      }
      else {
        iVar12 = 8;
      }
    }
  }
  if (iVar14 == 0) {
LAB_08028e96:
    uVar3 = 4;
  }
  else {
    if ((puVar11 < puVar5) && (iVar12 < 8)) {
      FUN_08028d14(puVar11,puVar5,iVar12);
    }
    if (param_3 < puVar11) {
      puVar5 = param_3 + -1;
      puVar8 = puVar11;
      do {
        puVar9 = puVar8 + 1;
        puVar5 = puVar5 + 1;
        *puVar5 = *puVar8;
        puVar8 = puVar9;
      } while (puVar9 <= puVar13);
      uVar6 = (int)puVar13 - (int)puVar11 & 0xfffffffc;
      if ((int)puVar10 - 3U < (int)puVar11 + 1U) {
        uVar6 = 0;
      }
      puVar10 = (uint *)((int)param_3 + uVar6 + 4);
      do {
        puVar11 = puVar10 + 1;
        *puVar10 = 0;
        puVar10 = puVar11;
      } while (puVar11 <= puVar13);
    }
    else if (uVar6 != 0) {
      puVar10[-1] = puVar10[-1] & 0xffffffffU >> (0x20 - uVar6 & 0xff);
    }
    for (; *puVar13 == 0; puVar13 = puVar13 + -1) {
      if (puVar13 == param_3) {
        *puVar13 = 1;
        break;
      }
    }
    uVar3 = 5;
  }
  return uVar3;
code_r0x08028e56:
  iVar4 = iVar7;
  if (param_3 < puVar11) {
    puVar11[-1] = 0;
    iVar12 = 1;
    puVar11 = puVar11 + -1;
LAB_08028e64:
    *puVar11 = uVar2 & 0xf | *puVar11 << 4;
    iVar4 = iVar7;
  }
  goto LAB_08028d8e;
}

