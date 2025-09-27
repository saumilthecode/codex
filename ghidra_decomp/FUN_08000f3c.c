
void FUN_08000f3c(int *param_1,uint *param_2)

{
  uint *extraout_r1;
  uint *extraout_r1_00;
  uint uVar1;
  uint uVar2;
  code *UNRECOVERED_JUMPTABLE;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  uint local_1c;
  
  puVar5 = (uint *)param_1[0x16];
  uVar4 = *DAT_080010e0;
  local_1c = 0;
  uVar2 = param_1[0x17];
  uVar3 = *puVar5;
  uVar1 = 8 << (uVar2 & 0xff);
  if (((uVar1 & uVar3) != 0) && (param_2 = (uint *)*param_1, (int)(*param_2 << 0x1d) < 0)) {
    *param_2 = *param_2 & 0xfffffffb;
    puVar5[2] = uVar1;
    param_1[0x15] = param_1[0x15] | 1;
  }
  uVar1 = 1 << (uVar2 & 0xff);
  if (((uVar1 & uVar3) != 0) && (param_2 = *(uint **)(*param_1 + 0x14), (int)param_2 << 0x18 < 0)) {
    puVar5[2] = uVar1;
    param_1[0x15] = param_1[0x15] | 2;
  }
  uVar1 = 4 << (uVar2 & 0xff);
  if (((uVar1 & uVar3) != 0) && (param_2 = (uint *)(*(int *)*param_1 << 0x1e), (int)param_2 < 0)) {
    puVar5[2] = uVar1;
    param_1[0x15] = param_1[0x15] | 4;
  }
  uVar1 = 0x10 << (uVar2 & 0xff);
  if (((uVar1 & uVar3) != 0) && (param_2 = (uint *)*param_1, (int)(*param_2 << 0x1c) < 0)) {
    puVar5[2] = uVar1;
    if ((*param_2 & 0x40000) == 0) {
      if (-1 < (int)(*param_2 << 0x17)) {
        *param_2 = *param_2 & 0xfffffff7;
      }
LAB_0800102c:
      UNRECOVERED_JUMPTABLE = (code *)param_1[0x10];
    }
    else {
      param_2 = (uint *)(*param_2 << 0xc);
      if (-1 < (int)param_2) goto LAB_0800102c;
      UNRECOVERED_JUMPTABLE = (code *)param_1[0x12];
    }
    if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
      (*UNRECOVERED_JUMPTABLE)(param_1);
      uVar2 = param_1[0x17];
      param_2 = extraout_r1_00;
    }
  }
  uVar1 = 0x20 << (uVar2 & 0xff);
  if (((uVar1 & uVar3) == 0) || (param_2 = (uint *)*param_1, -1 < (int)(*param_2 << 0x1b)))
  goto LAB_08000fc2;
  puVar5[2] = uVar1;
  if (*(char *)((int)param_1 + 0x35) == '\x05') {
    *param_2 = *param_2 & 0xffffffe9;
    param_2[5] = param_2[5] & 0xffffff7f;
    if ((param_1[0x10] != 0) || (param_1[0x12] != 0)) {
      *param_2 = *param_2 & 0xfffffff7;
    }
    UNRECOVERED_JUMPTABLE = (code *)param_1[0x14];
    puVar5[2] = 0x3f << (uVar2 & 0xff);
    *(undefined1 *)((int)param_1 + 0x35) = 1;
    *(undefined1 *)(param_1 + 0xd) = 0;
    if (UNRECOVERED_JUMPTABLE == (code *)0x0) {
      return;
    }
                    /* WARNING: Could not recover jumptable at 0x080010b0. Too many branches */
                    /* WARNING: Treating indirect jump as call */
    (*UNRECOVERED_JUMPTABLE)(param_1);
    return;
  }
  if ((*param_2 & 0x40000) == 0) {
    if ((*param_2 & 0x100) == 0) {
      *param_2 = *param_2 & 0xffffffef;
      *(undefined1 *)((int)param_1 + 0x35) = 1;
      *(undefined1 *)(param_1 + 0xd) = 0;
    }
LAB_08000fba:
    UNRECOVERED_JUMPTABLE = (code *)param_1[0xf];
  }
  else {
    param_2 = (uint *)(*param_2 << 0xc);
    if ((int)param_2 < 0) goto LAB_08000fba;
    UNRECOVERED_JUMPTABLE = (code *)param_1[0x11];
  }
  if (UNRECOVERED_JUMPTABLE != (code *)0x0) {
    (*UNRECOVERED_JUMPTABLE)(param_1);
    param_2 = extraout_r1;
  }
LAB_08000fc2:
  uVar1 = DAT_080010e4;
  if (param_1[0x15] != 0) {
    if (param_1[0x15] << 0x1f < 0) {
      puVar5 = (uint *)*param_1;
      *(undefined1 *)((int)param_1 + 0x35) = 5;
      param_2 = (uint *)((ulonglong)uVar1 * (ulonglong)uVar4);
      *puVar5 = *puVar5 & 0xfffffffe;
      do {
        local_1c = local_1c + 1;
        if ((uint)((ulonglong)uVar1 * (ulonglong)uVar4 >> 0x2a) < local_1c) break;
      } while ((int)(*puVar5 << 0x1f) < 0);
      *(undefined1 *)((int)param_1 + 0x35) = 1;
      *(undefined1 *)(param_1 + 0xd) = 0;
    }
    if ((code *)param_1[0x13] != (code *)0x0) {
                    /* WARNING: Could not recover jumptable at 0x0800100e. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      (*(code *)param_1[0x13])(param_1,param_2);
      return;
    }
  }
  return;
}

