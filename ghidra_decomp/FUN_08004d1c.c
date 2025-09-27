
undefined4 FUN_08004d1c(int *param_1)

{
  char cVar1;
  bool bVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *param_1;
  if ((*(char *)((int)param_1 + 0x41) == '!') && (*(int *)(iVar4 + 0x14) << 0x18 < 0)) {
    do {
      ExclusiveAccess((uint *)(iVar4 + 0x14));
      bVar2 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0x14));
    } while (!bVar2);
    *(uint *)(iVar4 + 0x14) = *(uint *)(iVar4 + 0x14) & 0xffffff7f;
    if (param_1[0xe] != 0) {
      FUN_08000d04();
      iVar4 = *param_1;
    }
    do {
      ExclusiveAccess((uint *)(iVar4 + 0xc));
      bVar2 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0xc));
    } while (!bVar2);
    *(uint *)(iVar4 + 0xc) = *(uint *)(iVar4 + 0xc) & 0xffffff3f;
    *(undefined1 *)((int)param_1 + 0x41) = 0x20;
    iVar3 = *(int *)(iVar4 + 0x14);
    cVar1 = *(char *)((int)param_1 + 0x42);
  }
  else {
    iVar3 = *(int *)(iVar4 + 0x14);
    cVar1 = *(char *)((int)param_1 + 0x42);
  }
  if ((cVar1 == '\"') && (iVar3 << 0x19 < 0)) {
    do {
      ExclusiveAccess((uint *)(iVar4 + 0x14));
      bVar2 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0x14));
    } while (!bVar2);
    *(uint *)(iVar4 + 0x14) = *(uint *)(iVar4 + 0x14) & 0xffffffbf;
    if (param_1[0xf] != 0) {
      FUN_08000d04();
      iVar4 = *param_1;
    }
    do {
      ExclusiveAccess((uint *)(iVar4 + 0xc));
      bVar2 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0xc));
    } while (!bVar2);
    *(uint *)(iVar4 + 0xc) = *(uint *)(iVar4 + 0xc) & 0xfffffedf;
    do {
      ExclusiveAccess((uint *)(iVar4 + 0x14));
      bVar2 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0x14));
    } while (!bVar2);
    *(uint *)(iVar4 + 0x14) = *(uint *)(iVar4 + 0x14) & 0xfffffffe;
    if (param_1[0xc] == 1) {
      do {
        ExclusiveAccess((uint *)(iVar4 + 0xc));
        bVar2 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0xc));
      } while (!bVar2);
      *(uint *)(iVar4 + 0xc) = *(uint *)(iVar4 + 0xc) & 0xffffffef;
    }
    *(undefined1 *)((int)param_1 + 0x42) = 0x20;
    param_1[0xc] = 0;
    return 0;
  }
  return 0;
}

