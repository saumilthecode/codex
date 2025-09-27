
undefined8 FUN_08003438(int *param_1)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  int iVar4;
  int local_18;
  
  iVar3 = (uint)((ulonglong)DAT_08003560 * (ulonglong)*DAT_0800355c >> 0x29) * 100;
  puVar2 = (uint *)*param_1;
  puVar2[1] = puVar2[1] & 0xffffffdf;
  if ((int)(puVar2[1] << 0x18) < 0) {
    param_1[0x11] = DAT_08003564;
    iVar4 = iVar3;
    do {
      if (iVar4 == 0) {
        param_1[0x15] = param_1[0x15] | 0x40;
        break;
      }
      iVar4 = iVar4 + -1;
    } while (*(char *)((int)param_1 + 0x51) != '\a');
  }
  if ((int)(puVar2[1] << 0x19) < 0) {
    param_1[0x10] = DAT_08003568;
    local_18 = iVar3;
    do {
      if (local_18 == 0) {
        param_1[0x15] = param_1[0x15] | 0x40;
        break;
      }
      local_18 = local_18 + -1;
    } while (*(char *)((int)param_1 + 0x51) != '\a');
  }
  if (((int)(puVar2[1] << 0x1e) < 0) && (param_1[0x12] != 0)) {
    *(undefined4 *)(param_1[0x12] + 0x50) = 0;
    iVar4 = FUN_08000d04();
    if (iVar4 != 0) {
      param_1[0x15] = 0x40;
    }
    puVar2 = (uint *)*param_1;
    puVar2[1] = puVar2[1] & 0xfffffffd;
    local_18 = iVar3;
    do {
      if (local_18 == 0) {
        param_1[0x15] = param_1[0x15] | 0x40;
        break;
      }
      local_18 = local_18 + -1;
    } while (-1 < (int)(puVar2[2] << 0x1e));
  }
  if (((int)(puVar2[1] << 0x1f) < 0) && (param_1[0x13] != 0)) {
    *(undefined4 *)(param_1[0x13] + 0x50) = 0;
    iVar3 = FUN_08000d04();
    if (iVar3 != 0) {
      param_1[0x15] = 0x40;
    }
    puVar2 = (uint *)*param_1;
    *puVar2 = *puVar2 & 0xffffffbf;
    puVar2[1] = puVar2[1] & 0xfffffffe;
  }
  *(undefined2 *)((int)param_1 + 0x3e) = 0;
  *(undefined2 *)((int)param_1 + 0x36) = 0;
  iVar3 = param_1[0x15];
  if (iVar3 != 0x40) {
    param_1[0x15] = 0;
  }
  uVar1 = puVar2[2];
  *(undefined1 *)((int)param_1 + 0x51) = 1;
  return CONCAT44(uVar1,(uint)(iVar3 == 0x40));
}

