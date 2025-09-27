
undefined4 FUN_080054d4(int *param_1)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *param_1;
  do {
    ExclusiveAccess((uint *)(iVar2 + 0xc));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0xc));
  } while (!bVar1);
  *(uint *)(iVar2 + 0xc) = *(uint *)(iVar2 + 0xc) & 0xffffff3f;
  if ((*(uint *)(iVar2 + 0x14) & 0x80) != 0) {
    do {
      ExclusiveAccess((uint *)(iVar2 + 0x14));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0x14));
    } while (!bVar1);
    *(uint *)(iVar2 + 0x14) = *(uint *)(iVar2 + 0x14) & 0xffffff7f;
    if (param_1[0xe] == 0) {
      *(undefined2 *)((int)param_1 + 0x26) = 0;
      *(undefined1 *)((int)param_1 + 0x41) = 0x20;
      FUN_080054d0(param_1);
      return 0;
    }
    *(undefined4 *)(param_1[0xe] + 0x50) = DAT_08005550;
    iVar2 = FUN_08000d98();
    if (iVar2 != 0) {
      (**(code **)(param_1[0xe] + 0x50))();
    }
    return 0;
  }
  *(undefined2 *)((int)param_1 + 0x26) = 0;
  *(undefined1 *)((int)param_1 + 0x41) = 0x20;
  FUN_080054d0(param_1);
  return 0;
}

