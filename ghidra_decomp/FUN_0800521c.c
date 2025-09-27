
void FUN_0800521c(undefined4 *param_1)

{
  bool bVar1;
  int iVar2;
  
  if ((*(uint *)*param_1 & 0x100) != 0) {
    FUN_08005218();
    return;
  }
  iVar2 = *(int *)param_1[0xe];
  *(undefined2 *)((int)param_1[0xe] + 0x26) = 0;
  do {
    ExclusiveAccess((uint *)(iVar2 + 0x14));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0x14));
  } while (!bVar1);
  *(uint *)(iVar2 + 0x14) = *(uint *)(iVar2 + 0x14) & 0xffffff7f;
  do {
    ExclusiveAccess((uint *)(iVar2 + 0xc));
    bVar1 = (bool)hasExclusiveAccess((uint *)(iVar2 + 0xc));
  } while (!bVar1);
  *(uint *)(iVar2 + 0xc) = *(uint *)(iVar2 + 0xc) | 0x40;
  return;
}

