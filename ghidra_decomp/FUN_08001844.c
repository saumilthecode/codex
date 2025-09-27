
/* WARNING: Type propagation algorithm not settling */

bool FUN_08001844(int *param_1)

{
  uint *puVar1;
  undefined4 *puVar2;
  uint *puVar3;
  int iVar4;
  int iVar5;
  uint uVar6;
  bool bVar7;
  
  puVar3 = DAT_08001c0c;
  puVar1 = DAT_08001ad8;
  if (param_1 == (int *)0x0) {
    return true;
  }
  iVar5 = *param_1;
  if (iVar5 << 0x1f < 0) {
    if (((DAT_08001ad8[2] & 0xc) == 4) ||
       (((DAT_08001ad8[2] & 0xc) == 8 && ((int)(DAT_08001ad8[1] << 9) < 0)))) {
      if (((int)(*DAT_08001ad8 << 0xe) < 0) && (param_1[1] == 0)) {
        return true;
      }
    }
    else {
      iVar5 = param_1[1];
      if (iVar5 == 0x10000) {
        *DAT_08001ad8 = *DAT_08001ad8 | 0x10000;
LAB_08001a62:
        iVar5 = FUN_0800061c();
        puVar1 = DAT_08001ad8;
        while (-1 < (int)(*puVar1 << 0xe)) {
          iVar4 = FUN_0800061c();
          if (100 < (uint)(iVar4 - iVar5)) {
            return (bool)3;
          }
        }
      }
      else {
        if (iVar5 == 0x50000) {
          *DAT_08001c0c = *DAT_08001c0c | 0x40000;
          *puVar3 = *puVar3 | 0x10000;
          goto LAB_08001a62;
        }
        *DAT_08001ad8 = *DAT_08001ad8 & 0xfffeffff;
        *puVar1 = *puVar1 & 0xfffbffff;
        if (iVar5 != 0) goto LAB_08001a62;
        iVar5 = FUN_0800061c();
        while ((int)(*puVar1 << 0xe) < 0) {
          iVar4 = FUN_0800061c();
          if (100 < (uint)(iVar4 - iVar5)) {
            return (bool)3;
          }
        }
      }
      iVar5 = *param_1;
    }
  }
  puVar3 = DAT_08001c0c;
  puVar1 = DAT_08001ad8;
  if (iVar5 << 0x1e < 0) {
    if (((DAT_08001ad8[2] & 0xc) == 0) ||
       (((DAT_08001ad8[2] & 0xc) == 8 && (-1 < (int)(DAT_08001ad8[1] << 9))))) {
      if (((int)(*DAT_08001ad8 << 0x1e) < 0) && (param_1[3] != 1)) {
        return true;
      }
      *DAT_08001ad8 = *DAT_08001ad8 & 0xffffff07 | param_1[4] << 3;
      puVar1 = DAT_08001ad8;
    }
    else if (param_1[3] == 0) {
      *DAT_08001c08 = 0;
      iVar5 = FUN_0800061c();
      while ((int)(*puVar3 << 0x1e) < 0) {
        iVar4 = FUN_0800061c();
        if (2 < (uint)(iVar4 - iVar5)) {
          return (bool)3;
        }
      }
      iVar5 = *param_1;
      puVar1 = DAT_08001ad8;
    }
    else {
      *DAT_08001adc = 1;
      iVar5 = FUN_0800061c();
      while (-1 < (int)(*puVar1 << 0x1e)) {
        iVar4 = FUN_0800061c();
        if (2 < (uint)(iVar4 - iVar5)) {
          return (bool)3;
        }
      }
      *puVar1 = *puVar1 & 0xffffff07 | param_1[4] << 3;
      iVar5 = *param_1;
      puVar1 = DAT_08001ad8;
    }
  }
  DAT_08001ad8 = puVar1;
  if (iVar5 << 0x1c < 0) {
    if (param_1[5] == 0) {
      DAT_08001adc[0x3a0] = 0;
      iVar5 = FUN_0800061c();
      while ((int)(puVar1[0x1d] << 0x1e) < 0) {
        iVar4 = FUN_0800061c();
        if (2 < (uint)(iVar4 - iVar5)) {
          return (bool)3;
        }
      }
    }
    else {
      DAT_08001adc[0x3a0] = 1;
      iVar5 = FUN_0800061c();
      while (-1 < (int)(puVar1[0x1d] << 0x1e)) {
        iVar4 = FUN_0800061c();
        if (2 < (uint)(iVar4 - iVar5)) {
          return (bool)3;
        }
      }
    }
    iVar5 = *param_1;
  }
  if (-1 < iVar5 << 0x1d) goto LAB_08001978;
  bVar7 = (DAT_08001ad8[0x10] & 0x10000000) == 0;
  if (bVar7) {
    DAT_08001ad8[0x10] = DAT_08001ad8[0x10] | 0x10000000;
  }
  puVar1 = DAT_08001ae0;
  if (-1 < (int)(*DAT_08001ae0 << 0x17)) {
    *DAT_08001ae0 = *DAT_08001ae0 | 0x100;
    iVar5 = FUN_0800061c();
    while (-1 < (int)(*puVar1 << 0x17)) {
      iVar4 = FUN_0800061c();
      if (2 < (uint)(iVar4 - iVar5)) {
        return (bool)3;
      }
    }
  }
  puVar3 = DAT_08001c0c;
  puVar1 = DAT_08001ad8;
  iVar5 = param_1[2];
  if (iVar5 == 1) {
    DAT_08001ad8[0x1c] = DAT_08001ad8[0x1c] | 1;
LAB_08001ac8:
    iVar5 = FUN_0800061c();
    puVar1 = DAT_08001ad8;
    while (-1 < (int)(puVar1[0x1c] << 0x1e)) {
      iVar4 = FUN_0800061c();
      if (5000 < (uint)(iVar4 - iVar5)) {
        return (bool)3;
      }
    }
  }
  else {
    if (iVar5 == 5) {
      DAT_08001c0c[0x1c] = DAT_08001c0c[0x1c] | 4;
      puVar3[0x1c] = puVar3[0x1c] | 1;
      goto LAB_08001ac8;
    }
    DAT_08001ad8[0x1c] = DAT_08001ad8[0x1c] & 0xfffffffe;
    puVar1[0x1c] = puVar1[0x1c] & 0xfffffffb;
    if (iVar5 != 0) goto LAB_08001ac8;
    iVar5 = FUN_0800061c();
    while ((int)(puVar1[0x1c] << 0x1e) < 0) {
      iVar4 = FUN_0800061c();
      if (5000 < (uint)(iVar4 - iVar5)) {
        return (bool)3;
      }
    }
  }
  if (bVar7) {
    DAT_08001c0c[0x10] = DAT_08001c0c[0x10] & 0xefffffff;
  }
LAB_08001978:
  puVar1 = DAT_08001ad8;
  iVar5 = param_1[6];
  if (iVar5 != 0) {
    if ((DAT_08001ad8[2] & 0xc) == 8) {
      if ((((iVar5 != 1) && (uVar6 = DAT_08001ad8[1], (uVar6 & 0x400000) == param_1[7])) &&
          ((uVar6 & 0x3f) == param_1[8])) &&
         (((uVar6 & 0x7fc0) == param_1[9] * 0x40 &&
          ((uVar6 & 0x30000) == (((uint)param_1[10] >> 1) - 1) * 0x10000)))) {
        return (uVar6 & 0xf000000) != param_1[0xb] * 0x1000000;
      }
      return true;
    }
    DAT_08001adc[0x18] = 0;
    if (iVar5 == 2) {
      iVar5 = FUN_0800061c();
      while (puVar2 = DAT_08001c08, (int)(*puVar1 << 6) < 0) {
        iVar4 = FUN_0800061c();
        if (2 < (uint)(iVar4 - iVar5)) {
          return (bool)3;
        }
      }
      puVar1[1] = param_1[7] | param_1[8] | param_1[9] << 6 | param_1[0xb] << 0x18 |
                  (((uint)param_1[10] >> 1) - 1) * 0x10000;
      puVar2[0x18] = 1;
      iVar5 = FUN_0800061c();
      puVar1 = DAT_08001c0c;
      while (-1 < (int)(*puVar1 << 6)) {
        iVar4 = FUN_0800061c();
        if (2 < (uint)(iVar4 - iVar5)) {
          return (bool)3;
        }
      }
    }
    else {
      iVar5 = FUN_0800061c();
      while ((int)(*puVar1 << 6) < 0) {
        iVar4 = FUN_0800061c();
        if (2 < (uint)(iVar4 - iVar5)) {
          return (bool)3;
        }
      }
    }
  }
  return false;
}

