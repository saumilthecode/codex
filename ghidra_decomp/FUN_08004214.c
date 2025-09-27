
void FUN_08004214(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  uint *puVar4;
  undefined4 uVar5;
  int *piVar6;
  
  piVar6 = *(int **)(param_1 + 0x38);
  puVar4 = (uint *)*piVar6;
  iVar2 = piVar6[0x13];
  *puVar4 = *puVar4 & 0xffffffbf;
  uVar3 = puVar4[1];
  *(undefined4 *)(iVar2 + 0x50) = 0;
  puVar4[1] = uVar3 & 0xfffffffe;
  uVar1 = FUN_0800061c();
  iVar2 = FUN_08002434(piVar6,uVar1);
  if (iVar2 != 0) {
    piVar6[0x15] = piVar6[0x15] | 0x40;
  }
  if ((piVar6[0x12] != 0) && (*(int *)(piVar6[0x12] + 0x50) != 0)) {
    return;
  }
  *(undefined2 *)((int)piVar6 + 0x3e) = 0;
  *(undefined2 *)((int)piVar6 + 0x36) = 0;
  if (piVar6[0x15] != 0x40) {
    piVar6[0x15] = 0;
  }
  uVar1 = *(undefined4 *)(*piVar6 + 8);
  uVar5 = *(undefined4 *)(*piVar6 + 8);
  *(undefined1 *)((int)piVar6 + 0x51) = 1;
  FUN_0800408c(piVar6,uVar1,uVar5);
  return;
}

