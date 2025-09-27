
undefined4 FUN_08005018(int *param_1)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *param_1;
  do {
    ExclusiveAccess((uint *)(iVar2 + 0xc));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0xc));
  } while (!bVar1);
  *(uint *)(iVar2 + 0xc) = *(uint *)(iVar2 + 0xc) & 0xfffffe1f;
  do {
    ExclusiveAccess((uint *)(iVar2 + 0x14));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0x14));
  } while (!bVar1);
  *(uint *)(iVar2 + 0x14) = *(uint *)(iVar2 + 0x14) & 0xfffffffe;
  if (param_1[0xc] == 1) {
    do {
      ExclusiveAccess((uint *)(iVar2 + 0xc));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0xc));
    } while (!bVar1);
    *(uint *)(iVar2 + 0xc) = *(uint *)(iVar2 + 0xc) & 0xffffffef;
  }
  if (*(int *)(iVar2 + 0x14) << 0x18 < 0) {
    do {
      ExclusiveAccess((uint *)(iVar2 + 0x14));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0x14));
    } while (!bVar1);
    *(uint *)(iVar2 + 0x14) = *(uint *)(iVar2 + 0x14) & 0xffffff7f;
    if (param_1[0xe] != 0) {
      *(undefined4 *)(param_1[0xe] + 0x50) = 0;
      iVar2 = FUN_08000d04();
      if ((iVar2 != 0) && (iVar2 = FUN_080011bc(param_1[0xe]), iVar2 == 0x20)) goto LAB_080050f0;
      iVar2 = *param_1;
    }
  }
  if (*(int *)(iVar2 + 0x14) << 0x19 < 0) {
    do {
      ExclusiveAccess((uint *)(iVar2 + 0x14));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0x14));
    } while (!bVar1);
    *(uint *)(iVar2 + 0x14) = *(uint *)(iVar2 + 0x14) & 0xffffffbf;
    if (param_1[0xf] != 0) {
      *(undefined4 *)(param_1[0xf] + 0x50) = 0;
      iVar2 = FUN_08000d04();
      if ((iVar2 != 0) && (iVar2 = FUN_080011bc(param_1[0xf]), iVar2 == 0x20)) {
LAB_080050f0:
        param_1[0x11] = 0x10;
        return 3;
      }
    }
  }
  *(undefined2 *)((int)param_1 + 0x26) = 0;
  *(undefined2 *)((int)param_1 + 0x2e) = 0;
  param_1[0x11] = 0;
  *(undefined1 *)((int)param_1 + 0x42) = 0x20;
  *(undefined1 *)((int)param_1 + 0x41) = 0x20;
  param_1[0xc] = 0;
  return 0;
}

