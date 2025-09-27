
void FUN_08005664(undefined4 *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  bool bVar1;
  int *piVar2;
  uint uVar3;
  int iVar4;
  
  piVar2 = (int *)param_1[0xe];
  uVar3 = *(uint *)*param_1 & 0x100;
  if (uVar3 == 0) {
    iVar4 = *piVar2;
    *(undefined2 *)((int)piVar2 + 0x2e) = 0;
    do {
      ExclusiveAccess((uint *)(iVar4 + 0xc));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0xc));
    } while (!bVar1);
    *(uint *)(iVar4 + 0xc) = *(uint *)(iVar4 + 0xc) & 0xfffffeff;
    do {
      ExclusiveAccess((uint *)(iVar4 + 0x14));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0x14));
    } while (!bVar1);
    *(uint *)(iVar4 + 0x14) = *(uint *)(iVar4 + 0x14) & 0xfffffffe;
    do {
      ExclusiveAccess((uint *)(iVar4 + 0x14));
      bVar1 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0x14));
    } while (!bVar1);
    *(uint *)(iVar4 + 0x14) = *(uint *)(iVar4 + 0x14) & 0xffffffbf;
    *(undefined1 *)((int)piVar2 + 0x42) = 0x20;
    uVar3 = piVar2[0xc];
    if (uVar3 == 1) {
      do {
        ExclusiveAccess((uint *)(iVar4 + 0xc));
        uVar3 = *(uint *)(iVar4 + 0xc) & 0xffffffef;
        bVar1 = (bool)hasExclusiveAccess((uint *)(iVar4 + 0xc));
      } while (!bVar1);
      *(uint *)(iVar4 + 0xc) = uVar3;
    }
  }
  piVar2[0xd] = 0;
  if (piVar2[0xc] != 1) {
    FUN_08005278();
    return;
  }
  FUN_08005640(piVar2,(short)piVar2[0xb],uVar3,1,param_4);
  return;
}

