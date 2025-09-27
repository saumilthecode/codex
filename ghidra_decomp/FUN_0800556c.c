
undefined4 FUN_0800556c(int *param_1)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *param_1;
  do {
    ExclusiveAccess((uint *)(iVar2 + 0xc));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0xc));
  } while (!bVar1);
  *(uint *)(iVar2 + 0xc) = *(uint *)(iVar2 + 0xc) & 0xfffffedf;
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
  if ((*(uint *)(iVar2 + 0x14) & 0x40) != 0) {
    do {
      ExclusiveAccess((uint *)(iVar2 + 0x14));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0x14));
    } while (!bVar1);
    *(uint *)(iVar2 + 0x14) = *(uint *)(iVar2 + 0x14) & 0xffffffbf;
    iVar2 = param_1[0xf];
    if (iVar2 != 0) {
      *(undefined4 *)(iVar2 + 0x50) = DAT_08005624;
      iVar2 = FUN_08000d98(iVar2);
      if (iVar2 != 0) {
        (**(code **)(param_1[0xf] + 0x50))();
      }
      return 0;
    }
    *(undefined2 *)((int)param_1 + 0x2e) = 0;
    *(undefined1 *)((int)param_1 + 0x42) = 0x20;
    param_1[0xc] = 0;
    FUN_08005568(param_1);
    return 0;
  }
  *(undefined2 *)((int)param_1 + 0x2e) = 0;
  *(undefined1 *)((int)param_1 + 0x42) = 0x20;
  param_1[0xc] = 0;
  FUN_08005568(param_1);
  return 0;
}

