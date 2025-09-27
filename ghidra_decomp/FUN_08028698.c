
undefined4 FUN_08028698(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  undefined4 *puVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  
  puVar1 = DAT_08028738;
  FUN_08028650(*DAT_08028738);
  iVar3 = DAT_08028740;
  iVar7 = *DAT_0802873c;
  if ((*DAT_0802873c == 0) &&
     (*DAT_0802873c = DAT_08028740, iVar7 = DAT_08028740, DAT_08028744 != (undefined4 *)0x0)) {
    *(undefined4 *)(iVar3 + 0x88) = *DAT_08028744;
    iVar7 = DAT_08028740;
  }
  uVar6 = *(uint *)(iVar7 + 4);
  if ((int)uVar6 < 0x20) {
    if (param_1 != 0) {
      iVar3 = *(int *)(iVar7 + 0x88);
      if (iVar3 == 0) {
        if ((DAT_08028748 == 0) || (iVar3 = FUN_080249b4(0x108), iVar3 == 0)) goto LAB_080286c8;
        *(undefined4 *)(iVar3 + 0x100) = 0;
        *(undefined4 *)(iVar3 + 0x104) = 0;
        *(int *)(iVar7 + 0x88) = iVar3;
      }
      uVar6 = *(uint *)(iVar7 + 4);
      *(undefined4 *)(iVar3 + uVar6 * 4) = param_3;
      uVar4 = 1 << (uVar6 & 0xff);
      uVar5 = *(uint *)(iVar3 + 0x100) | uVar4;
      *(uint *)(iVar3 + 0x100) = uVar5;
      *(undefined4 *)(iVar3 + uVar6 * 4 + 0x80) = param_4;
      if (param_1 == 2) {
        uVar5 = *(uint *)(iVar3 + 0x104) | uVar4;
      }
      if (param_1 == 2) {
        *(uint *)(iVar3 + 0x104) = uVar5;
      }
    }
    uVar2 = *puVar1;
    *(uint *)(iVar7 + 4) = uVar6 + 1;
    *(undefined4 *)(iVar7 + (uVar6 + 2) * 4) = param_2;
    FUN_08028654(uVar2);
    uVar2 = 0;
  }
  else {
LAB_080286c8:
    FUN_08028654(*puVar1);
    uVar2 = 0xffffffff;
  }
  return uVar2;
}

