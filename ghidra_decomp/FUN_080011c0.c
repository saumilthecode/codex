
void FUN_080011c0(uint *param_1,uint *param_2)

{
  uint *puVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  uint uVar9;
  int iVar10;
  int iVar11;
  
  iVar8 = DAT_08001484;
  puVar1 = DAT_08001480;
  uVar4 = *param_2;
  uVar3 = 0;
  if (param_1 == DAT_0800147c) {
    do {
      uVar2 = 1 << (uVar3 & 0xff);
      uVar7 = uVar4 & uVar2;
      if ((uVar2 & ~uVar4) == 0) {
        uVar5 = param_2[1];
        uVar2 = uVar3 << 1;
        uVar9 = uVar5 & 3;
        uVar6 = ~(3 << (uVar2 & 0xff));
        if (uVar9 - 1 < 2) {
          param_1[2] = param_2[3] << (uVar2 & 0xff) | uVar6 & param_1[2];
          param_1[1] = ((uVar5 << 0x1b) >> 0x1f) << (uVar3 & 0xff) | param_1[1] & ~uVar7;
          param_1[3] = param_2[2] << (uVar2 & 0xff) | uVar6 & param_1[3];
          if (uVar9 == 2) {
            iVar10 = (uVar3 >> 3) * 4;
            iVar11 = (uVar3 & 7) << 2;
            *(uint *)(iVar10 + 0x40020020) =
                 param_2[4] << iVar11 | *(uint *)(iVar10 + 0x40020020) & ~(0xf << iVar11);
          }
        }
        else if (uVar9 != 3) {
          param_1[3] = param_2[2] << (uVar2 & 0xff) | uVar6 & param_1[3];
        }
        *param_1 = uVar9 << (uVar2 & 0xff) | *param_1 & uVar6;
        if ((uVar5 & 0x30000) != 0) {
          *(uint *)(iVar8 + 0x44) = *(uint *)(iVar8 + 0x44) | 0x4000;
          *(uint *)((uVar3 & 0xfffffffc) + 0x40013808) =
               *(uint *)((uVar3 & 0xfffffffc) + 0x40013808) & ~(0xf << ((uVar3 & 3) << 2));
          uVar2 = ~uVar7;
          if ((uVar5 & 0x100000) == 0) {
            uVar6 = puVar1[2] & uVar2;
          }
          else {
            uVar6 = puVar1[2] | uVar7;
          }
          puVar1[2] = uVar6;
          if ((uVar5 & 0x200000) == 0) {
            uVar6 = puVar1[3] & uVar2;
          }
          else {
            uVar6 = puVar1[3] | uVar7;
          }
          puVar1[3] = uVar6;
          if ((uVar5 & 0x20000) == 0) {
            uVar6 = uVar2 & puVar1[1];
          }
          else {
            uVar6 = puVar1[1] | uVar7;
          }
          puVar1[1] = uVar6;
          if ((int)(uVar5 << 0xf) < 0) {
            uVar2 = *puVar1 | uVar7;
          }
          else {
            uVar2 = uVar2 & *puVar1;
          }
          *puVar1 = uVar2;
        }
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 != 0x10);
  }
  else {
    do {
      uVar2 = 1 << (uVar3 & 0xff);
      uVar7 = uVar2 & uVar4;
      if ((uVar2 & ~uVar4) == 0) {
        uVar5 = param_2[1];
        uVar9 = uVar5 & 3;
        uVar2 = uVar3 << 1;
        uVar6 = ~(3 << (uVar2 & 0xff));
        if (uVar9 - 1 < 2) {
          param_1[2] = param_2[3] << (uVar2 & 0xff) | param_1[2] & uVar6;
          param_1[1] = ((uVar5 << 0x1b) >> 0x1f) << (uVar3 & 0xff) | param_1[1] & ~uVar7;
          param_1[3] = param_2[2] << (uVar2 & 0xff) | param_1[3] & uVar6;
          if (uVar9 == 2) {
            iVar8 = (uVar3 & 7) << 2;
            param_1[(uVar3 >> 3) + 8] =
                 param_2[4] << iVar8 | param_1[(uVar3 >> 3) + 8] & ~(0xf << iVar8);
          }
        }
        else if (uVar9 != 3) {
          param_1[3] = param_2[2] << (uVar2 & 0xff) | param_1[3] & uVar6;
        }
        *param_1 = uVar9 << (uVar2 & 0xff) | uVar6 & *param_1;
        if ((uVar5 & 0x30000) != 0) {
          *(uint *)(DAT_08001484 + 0x44) = *(uint *)(DAT_08001484 + 0x44) | 0x4000;
          iVar8 = (uVar3 & 3) << 2;
          uVar2 = *(uint *)((uVar3 & 0xfffffffc) + 0x40013808) & ~(0xf << iVar8);
          if (param_1 == DAT_08001488) {
            uVar2 = uVar2 | 1 << iVar8;
          }
          else if (param_1 == DAT_0800148c) {
            uVar2 = uVar2 | 2 << iVar8;
          }
          else if (param_1 == DAT_08001490) {
            uVar2 = uVar2 | 3 << iVar8;
          }
          else if (param_1 == DAT_08001494) {
            uVar2 = uVar2 | 4 << iVar8;
          }
          else if (param_1 == DAT_08001498) {
            uVar2 = uVar2 | 5 << iVar8;
          }
          else if (param_1 == DAT_0800149c) {
            uVar2 = uVar2 | 6 << iVar8;
          }
          else {
            if (param_1 == DAT_080014a0) {
              iVar10 = 7;
            }
            else {
              iVar10 = 8;
            }
            uVar2 = uVar2 | iVar10 << iVar8;
          }
          *(uint *)((uVar3 & 0xfffffffc) + 0x40013808) = uVar2;
          uVar2 = ~uVar7;
          if ((int)(uVar5 << 0xb) < 0) {
            uVar6 = puVar1[2] | uVar7;
          }
          else {
            uVar6 = puVar1[2] & uVar2;
          }
          puVar1[2] = uVar6;
          if ((int)(uVar5 << 10) < 0) {
            uVar6 = puVar1[3] | uVar7;
          }
          else {
            uVar6 = puVar1[3] & uVar2;
          }
          puVar1[3] = uVar6;
          if ((int)(uVar5 << 0xe) < 0) {
            uVar6 = puVar1[1] | uVar7;
          }
          else {
            uVar6 = puVar1[1] & uVar2;
          }
          puVar1[1] = uVar6;
          if ((int)(uVar5 << 0xf) < 0) {
            uVar2 = *puVar1 | uVar7;
          }
          else {
            uVar2 = *puVar1 & uVar2;
          }
          *puVar1 = uVar2;
        }
      }
      uVar3 = uVar3 + 1;
    } while (uVar3 != 0x10);
  }
  return;
}

