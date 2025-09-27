
void FUN_0801faf0(int param_1,undefined1 *param_2,int param_3)

{
  undefined1 *puVar1;
  uint uVar2;
  uint uVar3;
  undefined1 uVar4;
  undefined1 *puVar5;
  uint uVar6;
  bool bVar7;
  
  uVar6 = *(uint *)(param_1 + 0xc);
  uVar4 = 0x25;
  bVar7 = (int)(uVar6 << 0x14) < 0;
  *param_2 = 0x25;
  if (bVar7) {
    uVar4 = 0x2b;
  }
  if (bVar7) {
    param_2[1] = uVar4;
    param_2 = param_2 + 2;
  }
  else {
    param_2 = param_2 + 1;
  }
  puVar1 = param_2;
  if ((int)(uVar6 << 0x15) < 0) {
    puVar1 = param_2 + 1;
    *param_2 = 0x23;
  }
  uVar3 = uVar6 & 0x104;
  if (uVar3 == 0x104) {
    if (param_3 != 0) goto LAB_0801fb26;
LAB_0801fb52:
    bVar7 = (uVar6 & 0x4000) == 0;
    if (bVar7) {
      uVar3 = 0x61;
    }
    uVar4 = (undefined1)uVar3;
    if (!bVar7) {
      uVar4 = 0x41;
    }
    *puVar1 = uVar4;
  }
  else {
    puVar5 = puVar1 + 2;
    *puVar1 = 0x2e;
    puVar1[1] = 0x2a;
    puVar1 = puVar5;
    if (param_3 != 0) {
LAB_0801fb26:
      puVar5 = puVar1 + 1;
      *puVar1 = (char)param_3;
    }
    puVar1 = puVar5;
    if (uVar3 == 4) {
      uVar4 = 0x66;
    }
    else {
      uVar2 = uVar6 & 0x4000;
      if (uVar3 == 0x100) {
        if (uVar2 == 0) {
          uVar4 = 0x65;
        }
        else {
          uVar4 = 0x45;
        }
      }
      else {
        if (uVar3 == 0x104) goto LAB_0801fb52;
        if (uVar2 == 0) {
          uVar3 = 0x67;
        }
        uVar4 = (undefined1)uVar3;
        if (uVar2 != 0) {
          uVar4 = 0x47;
        }
      }
    }
    *puVar5 = uVar4;
  }
  puVar1[1] = 0;
  return;
}

