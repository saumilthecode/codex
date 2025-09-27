
void FUN_08003b1c(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = (int *)param_1[0xe];
  uVar1 = FUN_0800061c();
  if (-1 < *(int *)*param_1 << 0x17) {
    iVar2 = *piVar3;
    *(uint *)(iVar2 + 4) = *(uint *)(iVar2 + 4) & 0xffffffdf;
    *(uint *)(iVar2 + 4) = *(uint *)(iVar2 + 4) & 0xfffffffd;
    iVar2 = FUN_08002434(piVar3,uVar1);
    if (iVar2 != 0) {
      piVar3[0x15] = piVar3[0x15] | 0x20;
    }
    *(undefined2 *)((int)piVar3 + 0x36) = 0;
    *(undefined1 *)((int)piVar3 + 0x51) = 1;
    if (piVar3[0x15] != 0) {
      FUN_0800363c(piVar3);
      return;
    }
  }
  FUN_08003600(piVar3);
  return;
}

