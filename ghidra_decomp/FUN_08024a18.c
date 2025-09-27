
uint FUN_08024a18(undefined4 *param_1,uint param_2)

{
  uint *puVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  uint *puVar7;
  uint uVar8;
  
  puVar6 = DAT_08024b14;
  uVar8 = (param_2 + 3 & 0xfffffffc) + 8;
  if (uVar8 < 0xc) {
    uVar8 = 0xc;
  }
  if (((int)uVar8 < 0) || (uVar8 < param_2)) {
    *param_1 = 0xc;
  }
  else {
    FUN_08024b18();
    puVar7 = (uint *)*puVar6;
    for (puVar1 = (uint *)*puVar6; puVar1 != (uint *)0x0; puVar1 = (uint *)puVar1[1]) {
      uVar4 = *puVar1 - uVar8;
      if (-1 < (int)uVar4) {
        if (uVar4 < 0xc) {
          uVar8 = puVar1[1];
          if (puVar7 == puVar1) {
            *puVar6 = uVar8;
          }
          if (puVar7 != puVar1) {
            puVar7[1] = uVar8;
          }
        }
        else {
          uVar3 = (int)puVar1 + uVar8;
          *puVar1 = uVar8;
          if (puVar7 != puVar1) {
            puVar7[1] = uVar3;
          }
          uVar5 = puVar1[1];
          if (puVar7 == puVar1) {
            *puVar6 = uVar3;
          }
          *(uint *)((int)puVar1 + uVar8) = uVar4;
          *(uint *)(uVar3 + 4) = uVar5;
        }
        goto LAB_08024ac0;
      }
      puVar7 = puVar1;
    }
    puVar1 = (uint *)FUN_080249d4(param_1,uVar8);
    if (puVar1 != (uint *)0xffffffff) {
      *puVar1 = uVar8;
LAB_08024ac0:
      FUN_08024b24(param_1);
      puVar6 = puVar1 + 1;
      uVar8 = (int)puVar1 + 0xbU & 0xfffffff8;
      iVar2 = uVar8 - (int)puVar6;
      if (iVar2 != 0) {
        puVar6 = (uint *)((int)puVar6 - uVar8);
      }
      if (iVar2 == 0) {
        return uVar8;
      }
      *(uint **)((int)puVar1 + iVar2) = puVar6;
      return uVar8;
    }
    puVar1 = (uint *)*puVar6;
    for (puVar7 = (uint *)*puVar6; puVar7 != (uint *)0x0; puVar7 = (uint *)puVar7[1]) {
      puVar1 = puVar7;
    }
    if ((puVar1 != (uint *)0x0) &&
       (uVar4 = *puVar1, iVar2 = FUN_080285b4(param_1,0), (int)puVar1 + uVar4 == iVar2)) {
      uVar4 = *puVar1;
      iVar2 = FUN_080249d4(param_1,uVar8 - uVar4);
      if (iVar2 != -1) {
        *puVar1 = *puVar1 + (uVar8 - uVar4);
        puVar7 = (uint *)*puVar6;
        if (((uint *)*puVar6)[1] == 0) {
          *puVar6 = 0;
        }
        else {
          do {
            puVar6 = puVar7;
            puVar7 = (uint *)puVar6[1];
          } while (puVar7 != puVar1);
          puVar6[1] = 0;
        }
        goto LAB_08024ac0;
      }
    }
    *param_1 = 0xc;
    FUN_08024b24(param_1);
  }
  return 0;
}

