
undefined8 FUN_0802969c(int param_1)

{
  int iVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  undefined8 uVar8;
  
  uVar2 = DAT_0802972c;
  uVar7 = param_1 + 0x14;
  uVar3 = uVar7 + *(int *)(param_1 + 0x10) * 4;
  uVar5 = *(uint *)(uVar3 - 4);
  uVar8 = FUN_0802914c(uVar5);
  iVar1 = (int)uVar8;
  uVar6 = uVar3 - 4;
  *(int *)((ulonglong)uVar8 >> 0x20) = 0x20 - iVar1;
  if (iVar1 < 0xb) {
    if (uVar7 < uVar6) {
      uVar3 = *(uint *)(uVar3 - 8);
    }
    if (uVar7 >= uVar6) {
      uVar3 = 0;
    }
    uVar2 = uVar5 >> (0xbU - iVar1 & 0xff) | uVar2;
    uVar3 = uVar3 >> (0xbU - iVar1 & 0xff) | uVar5 << (iVar1 + 0x15U & 0xff);
  }
  else {
    if (uVar7 < uVar6) {
      uVar6 = uVar3 - 8;
      uVar3 = *(uint *)(uVar3 - 8);
    }
    else {
      uVar3 = 0;
    }
    uVar4 = iVar1 - 0xb;
    if (uVar4 == 0) {
      uVar2 = uVar5 | uVar2;
    }
    else {
      if (uVar7 < uVar6) {
        uVar6 = *(uint *)(uVar6 - 4);
      }
      else {
        uVar6 = 0;
      }
      uVar2 = uVar5 << (uVar4 & 0xff) | uVar3 >> (0x20 - uVar4 & 0xff) | 0x3ff00000;
      uVar3 = uVar3 << (uVar4 & 0xff) | uVar6 >> (0x20 - uVar4 & 0xff);
    }
  }
  return CONCAT44(uVar2,uVar3);
}

