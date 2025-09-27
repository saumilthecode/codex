
int FUN_08029418(undefined4 param_1,int param_2,uint param_3,undefined4 param_4)

{
  int iVar1;
  int extraout_r1;
  undefined4 *puVar2;
  uint *puVar3;
  int iVar4;
  uint *puVar5;
  uint *puVar6;
  uint *puVar7;
  uint uVar8;
  int iVar9;
  int iVar10;
  uint *puVar11;
  
  iVar1 = *(int *)(param_2 + 4);
  uVar8 = (int)param_3 >> 5;
  iVar9 = *(int *)(param_2 + 0x10) + uVar8;
  iVar4 = *(int *)(param_2 + 8);
  iVar10 = iVar9 + 1;
  do {
    if (iVar10 <= iVar4) {
      iVar1 = FUN_08028f6c(param_1,iVar1);
      if (iVar1 != 0) break;
      iVar4 = DAT_080294ec;
      FUN_08028754(DAT_080294f0,0x1de,0);
      iVar1 = extraout_r1;
    }
    iVar1 = iVar1 + 1;
    iVar4 = iVar4 << 1;
  } while( true );
  puVar2 = (undefined4 *)(iVar1 + 0x10);
  for (iVar4 = 0; iVar4 < (int)uVar8; iVar4 = iVar4 + 1) {
    puVar2 = puVar2 + 1;
    *puVar2 = 0;
  }
  puVar11 = (uint *)(iVar1 + 0x14 + (uVar8 & ~((int)param_3 >> 0x1f)) * 4);
  puVar5 = (uint *)(param_2 + 0x14);
  param_3 = param_3 & 0x1f;
  puVar3 = puVar5 + *(int *)(param_2 + 0x10);
  if (param_3 == 0) {
    do {
      puVar7 = puVar5 + 1;
      *puVar11 = *puVar5;
      puVar11 = puVar11 + 1;
      puVar5 = puVar7;
    } while (puVar7 < puVar3);
  }
  else {
    uVar8 = 0;
    puVar7 = puVar11;
    do {
      *puVar7 = *puVar5 << param_3 | uVar8;
      puVar6 = puVar5 + 1;
      puVar7 = puVar7 + 1;
      uVar8 = *puVar5 >> (0x20 - param_3 & 0xff);
      puVar5 = puVar6;
    } while (puVar6 < puVar3);
    puVar7 = (uint *)((int)puVar3 + (-0x15 - param_2) & 0xfffffffc);
    if (puVar3 < (uint *)(param_2 + 0x15)) {
      puVar7 = (uint *)0x0;
    }
    *(uint *)((int)puVar11 + (int)puVar7 + 4) = uVar8;
    if (uVar8 != 0) goto LAB_080294c0;
  }
  iVar10 = iVar9;
LAB_080294c0:
  *(int *)(iVar1 + 0x10) = iVar10;
  FUN_08028fe8(param_1,param_2,puVar3,puVar7,param_4);
  return iVar1;
}

