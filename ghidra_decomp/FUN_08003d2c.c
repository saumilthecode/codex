
uint FUN_08003d2c(undefined4 *param_1)

{
  uint uVar1;
  uint uVar2;
  uint *puVar3;
  uint uVar4;
  int iVar5;
  code *UNRECOVERED_JUMPTABLE;
  
  puVar3 = (uint *)*param_1;
  uVar2 = puVar3[1];
  uVar4 = puVar3[2];
  if ((uVar4 & 0x40) == 0) {
    if (((uVar4 & 1) != 0) && ((uVar2 & 0x40) != 0)) {
      UNRECOVERED_JUMPTABLE = (code *)param_1[0x10];
      goto LAB_08003e7e;
    }
    uVar1 = uVar4 << 0x1e;
    if ((int)uVar1 < 0) {
      if ((int)(uVar2 << 0x18) < 0) goto LAB_08003e7a;
      uVar1 = uVar4 << 0x1a;
      if ((int)uVar1 < 0) goto LAB_08003de0;
    }
    else if ((int)(uVar4 << 0x1a) < 0) {
      if (-1 < (int)(uVar2 << 0x1a)) {
        return uVar2 << 0x1a;
      }
      goto LAB_08003e04;
    }
    if (-1 < (int)(uVar4 << 0x17)) {
      return uVar1;
    }
    if (-1 < (int)(uVar2 << 0x1a)) {
      return uVar1;
    }
  }
  else {
    if ((uVar4 & 2) == 0) {
      if (-1 < (int)(uVar2 << 0x1a)) {
        return 0;
      }
      if (*(char *)((int)param_1 + 0x51) == '\x03') {
        return 0;
      }
      param_1[0x15] = param_1[0x15] | 4;
      uVar1 = uVar4 << 0x1a;
      if ((int)uVar1 < 0) {
LAB_08003e04:
        param_1[0x15] = param_1[0x15] | 1;
        uVar1 = puVar3[2];
        *puVar3 = *puVar3 & 0xffffffbf;
      }
    }
    else {
      if ((int)(uVar2 << 0x18) < 0) {
LAB_08003e7a:
        UNRECOVERED_JUMPTABLE = (code *)param_1[0x11];
LAB_08003e7e:
                    /* WARNING: Could not recover jumptable at 0x08003e84. Too many branches */
                    /* WARNING: Treating indirect jump as call */
        uVar2 = (*UNRECOVERED_JUMPTABLE)(param_1);
        return uVar2;
      }
      if ((uVar4 & 0x20) != 0) {
LAB_08003de0:
        if (-1 < (int)(uVar2 << 0x1a)) {
          return uVar2 << 0x1a;
        }
        if ((int)(uVar4 << 0x19) < 0) {
          if (*(char *)((int)param_1 + 0x51) == '\x03') {
            return 3;
          }
          param_1[0x15] = param_1[0x15] | 4;
        }
        goto LAB_08003e04;
      }
      if (-1 < (int)(uVar2 << 0x1a)) {
        return 0;
      }
      if (*(char *)((int)param_1 + 0x51) == '\x03') {
        return 0;
      }
      param_1[0x15] = param_1[0x15] | 4;
      uVar1 = puVar3[2];
    }
    if (-1 < (int)(uVar4 << 0x17)) {
      iVar5 = param_1[0x15];
      goto joined_r0x08003e26;
    }
  }
  uVar1 = 0;
  param_1[0x15] = param_1[0x15] | 8;
  iVar5 = param_1[0x15];
joined_r0x08003e26:
  if (iVar5 != 0) {
    puVar3[1] = puVar3[1] & 0xffffff1f;
    *(undefined1 *)((int)param_1 + 0x51) = 1;
    if ((uVar2 & 3) == 0) {
      uVar1 = FUN_0800363c(param_1);
    }
    else {
      iVar5 = param_1[0x13];
      puVar3[1] = puVar3[1] & 0xfffffffc;
      if (iVar5 != 0) {
        *(undefined4 *)(iVar5 + 0x50) = DAT_08003ea0;
        iVar5 = FUN_08000d98();
        if (iVar5 != 0) {
          param_1[0x15] = param_1[0x15] | 0x40;
        }
      }
      uVar1 = param_1[0x12];
      if (uVar1 != 0) {
        *(undefined4 *)(uVar1 + 0x50) = DAT_08003ea0;
        uVar1 = FUN_08000d98();
        if (uVar1 != 0) {
          param_1[0x15] = param_1[0x15] | 0x40;
        }
      }
    }
  }
  return uVar1;
}

