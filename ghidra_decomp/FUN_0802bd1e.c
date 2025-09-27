
undefined4 FUN_0802bd1e(uint *param_1,undefined4 param_2,uint param_3,int param_4)

{
  int iVar1;
  undefined4 *puVar2;
  undefined4 *puVar3;
  uint uVar4;
  uint uVar5;
  uint *puVar6;
  undefined4 *puVar7;
  uint uVar8;
  bool bVar9;
  undefined4 auStack_1a4 [33];
  undefined1 auStack_120 [128];
  undefined4 auStack_a0 [34];
  
  switch(param_2) {
  case 0:
    if (param_4 != 0) {
      return 2;
    }
    puVar6 = (uint *)param_1[0xe];
    uVar5 = 0;
    do {
      if ((1 << (uVar5 & 0xff) & param_3 & 0xffff) != 0) {
        param_1[uVar5 + 1] = *puVar6;
        puVar6 = puVar6 + 1;
      }
      uVar5 = uVar5 + 1;
    } while (uVar5 != 0x10);
    if ((int)(param_3 << 0x12) < 0) {
      return 0;
    }
    break;
  case 1:
    uVar5 = param_3 >> 0x10;
    param_3 = param_3 & 0xffff;
    if (param_4 == 1) {
      if (0x10 < uVar5 + param_3) {
        return 2;
      }
      if (uVar5 == 0x10) {
        return 2;
      }
LAB_0802bdbe:
      uVar4 = 0;
LAB_0802bee4:
      uVar8 = *param_1;
      if ((int)(uVar8 << 0x1f) < 0) {
        if (param_4 == 5) {
          *param_1 = uVar8 & 0xfffffffe | 2;
          FUN_080069e0();
        }
        else {
          *param_1 = uVar8 & 0xfffffffc;
          FUN_080069d0(param_1 + 0x14);
        }
      }
      if (uVar4 != 0) {
LAB_0802bda0:
        if ((int)(*param_1 << 0x1d) < 0) {
          *param_1 = *param_1 & 0xfffffffb;
          FUN_080069f0(param_1 + 0x36);
        }
      }
      if (param_4 == 1) {
        FUN_080069d0(auStack_a0);
        if (uVar4 == 0) goto LAB_0802bdfc;
      }
      else {
        if (uVar5 < 0x10) {
          FUN_080069e0(auStack_a0);
        }
        if (uVar4 == 0) goto LAB_0802bdfc;
        FUN_080069f0(auStack_120);
      }
      param_3 = 0x10 - uVar5;
    }
    else {
      if (param_4 != 5) {
        return 2;
      }
      uVar4 = uVar5 + param_3;
      if (0x20 < uVar4) {
        return 2;
      }
      if (uVar5 < 0x10) {
        if (uVar4 < 0x11) goto LAB_0802bdbe;
        uVar4 = uVar4 - 0x10;
        goto LAB_0802bee4;
      }
      uVar4 = param_3;
      if (param_3 != 0) goto LAB_0802bda0;
LAB_0802bdfc:
      uVar4 = 0;
    }
    puVar7 = (undefined4 *)param_1[0xe];
    if (0 < (int)param_3) {
      iVar1 = param_3 << 1;
      puVar3 = auStack_a0 + uVar5 * 2;
      while( true ) {
        bVar9 = iVar1 == 0;
        iVar1 = iVar1 + -1;
        if (bVar9) break;
        *puVar3 = *(undefined4 *)((int)puVar3 + ((int)puVar7 - (int)(auStack_a0 + uVar5 * 2)));
        puVar3 = puVar3 + 1;
      }
      puVar7 = puVar7 + param_3 * 2;
    }
    if (uVar4 != 0) {
      uVar8 = uVar5;
      if (uVar5 < 0x10) {
        uVar8 = 0x10;
      }
      iVar1 = (int)(short)uVar4 << 1;
      puVar3 = auStack_1a4 + uVar8 * 2;
      puVar2 = puVar7;
      while (bVar9 = iVar1 != 0, iVar1 = iVar1 + -1, bVar9) {
        puVar3 = puVar3 + 1;
        *puVar3 = *puVar2;
        puVar2 = puVar2 + 1;
      }
      puVar7 = puVar7 + uVar4 * 2;
    }
    if (param_4 != 1) {
      param_1[0xe] = (uint)puVar7;
      if (uVar5 < 0x10) {
        FUN_080069d8(auStack_a0);
      }
      if (uVar4 == 0) {
        return 0;
      }
      FUN_080069e8(auStack_120);
      return 0;
    }
    param_1[0xe] = (uint)(puVar7 + 1);
    FUN_080069c8(auStack_a0);
    return 0;
  default:
    return 2;
  case 3:
    if (param_4 != 3) {
      return 2;
    }
    uVar5 = param_3 & 0xffff;
    if (0x10 < uVar5 + (param_3 >> 0x10)) {
      return 2;
    }
    if ((int)(*param_1 << 0x1c) < 0) {
      *param_1 = *param_1 & 0xfffffff7;
      FUN_08006a3c(param_1 + 0x56);
    }
    FUN_08006a3c(auStack_a0);
    uVar4 = param_1[0xe];
    puVar3 = auStack_a0 + (param_3 >> 0x10) * 2;
    iVar1 = uVar5 << 1;
    puVar7 = puVar3;
    while( true ) {
      bVar9 = iVar1 == 0;
      iVar1 = iVar1 + -1;
      if (bVar9) break;
      *puVar7 = *(undefined4 *)((int)puVar7 + (uVar4 - (int)puVar3));
      puVar7 = puVar7 + 1;
    }
    param_1[0xe] = uVar4 + uVar5 * 8;
    FUN_080069f8(auStack_a0);
    return 0;
  case 4:
    if (param_4 != 0) {
      return 2;
    }
    if (param_3 < 0x11) {
      if ((int)(*param_1 << 0x1b) < 0) {
        *param_1 = *param_1 & 0xffffffef;
        FUN_08006a94(param_1 + 0x76);
      }
      FUN_08006a94(auStack_a0);
      puVar7 = (undefined4 *)param_1[0xe];
      uVar5 = 0;
      do {
        if ((1 << (uVar5 & 0xff) & param_3) != 0) {
          auStack_a0[uVar5] = *puVar7;
          puVar7 = puVar7 + 1;
        }
        uVar5 = uVar5 + 1;
      } while (uVar5 != 4);
      param_1[0xe] = (uint)puVar7;
      FUN_08006a80(auStack_a0);
      return 0;
    }
    return 2;
  case 5:
    if (param_3 != 0) {
      return 2;
    }
    puVar6 = (uint *)param_1[0xe] + 1;
    param_1[0x11] = *(uint *)param_1[0xe];
  }
  param_1[0xe] = (uint)puVar6;
  return 0;
}

