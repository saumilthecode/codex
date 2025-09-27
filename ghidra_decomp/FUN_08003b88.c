
void FUN_08003b88(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  uint *puVar4;
  int *piVar5;
  
  piVar5 = (int *)param_1[0xe];
  uVar1 = FUN_0800061c();
  if (*(int *)*param_1 << 0x17 < 0) goto LAB_08003bfa;
  puVar4 = (uint *)*piVar5;
  iVar2 = piVar5[10];
  puVar4[1] = puVar4[1] & 0xffffffdf;
  if (iVar2 == 0x2000) {
    iVar2 = FUN_08002374(piVar5,1);
    if (iVar2 != 0) {
      piVar5[0x15] = piVar5[0x15] | 2;
    }
    puVar4 = (uint *)*piVar5;
  }
  iVar2 = piVar5[1];
  iVar3 = piVar5[2];
  if (iVar3 == 0) {
    if (iVar2 == 0x104) {
      puVar4[1] = puVar4[1] & 0xfffffffc;
      goto LAB_08003c2c;
    }
    puVar4[1] = puVar4[1] & 0xfffffffe;
LAB_08003bc8:
    iVar2 = FUN_08002374(piVar5,1,0,uVar1);
  }
  else {
    puVar4[1] = puVar4[1] & 0xfffffffe;
    if (iVar2 != 0x104) goto LAB_08003bc8;
    if (iVar3 == 0x8000) {
      *puVar4 = *puVar4 & 0xffffffbf;
    }
    else if (iVar3 == 0x400) {
      *puVar4 = *puVar4 & 0xffffffbf;
      goto LAB_08003bc8;
    }
LAB_08003c2c:
    iVar2 = FUN_08002374(piVar5,0x80,0,uVar1);
  }
  if (iVar2 != 0) {
    piVar5[0x15] = piVar5[0x15] | 0x20;
    piVar5[0x15] = 0x20;
  }
  *(undefined2 *)((int)piVar5 + 0x3e) = 0;
  *(undefined1 *)((int)piVar5 + 0x51) = 1;
  if (*(int *)(*piVar5 + 8) << 0x1b < 0) {
    piVar5[0x15] = piVar5[0x15] | 2;
    *(undefined4 *)(*piVar5 + 8) = 0xffef;
  }
  if (piVar5[0x15] != 0) {
    FUN_0800363c(piVar5);
    return;
  }
LAB_08003bfa:
  FUN_08003604(piVar5);
  return;
}

