
void FUN_08020638(int param_1)

{
  undefined1 *puVar1;
  undefined4 uVar2;
  undefined4 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  puVar3 = *(undefined4 **)(param_1 + 8);
  if (puVar3 == (undefined4 *)0x0) {
    puVar3 = (undefined4 *)FUN_08008466(0x68);
    puVar3[2] = 0;
    puVar3[3] = 0;
    puVar3[5] = 0;
    puVar3[6] = 0;
    puVar3[7] = 0;
    puVar3[8] = 0;
    uVar2 = DAT_080206bc;
    puVar3[1] = 0;
    *puVar3 = uVar2;
    *(undefined1 *)(puVar3 + 4) = 0;
    *(undefined2 *)(puVar3 + 9) = 0;
    *(undefined1 *)(puVar3 + 0x19) = 0;
    *(undefined4 **)(param_1 + 8) = puVar3;
  }
  *(undefined1 *)(puVar3 + 9) = 0x2e;
  iVar4 = *(int *)(param_1 + 8);
  puVar3[2] = DAT_080206c0;
  iVar6 = 0;
  puVar3[3] = 0;
  *(undefined1 *)(puVar3 + 4) = 0;
  *(undefined1 *)(iVar4 + 0x25) = 0x2c;
  iVar4 = *DAT_080206c4;
  do {
    puVar1 = (undefined1 *)(iVar4 + iVar6);
    iVar5 = *(int *)(param_1 + 8) + iVar6;
    iVar6 = iVar6 + 1;
    *(undefined1 *)(iVar5 + 0x26) = *puVar1;
  } while (iVar6 != 0x24);
  iVar4 = *DAT_080206c8;
  iVar6 = 0;
  do {
    puVar1 = (undefined1 *)(iVar4 + iVar6);
    iVar5 = *(int *)(param_1 + 8) + iVar6;
    iVar6 = iVar6 + 1;
    *(undefined1 *)(iVar5 + 0x4a) = *puVar1;
  } while (iVar6 != 0x1a);
  iVar4 = *(int *)(param_1 + 8);
  *(undefined4 *)(iVar4 + 0x14) = DAT_080206cc;
  *(undefined4 *)(iVar4 + 0x18) = 4;
  *(undefined4 *)(iVar4 + 0x1c) = DAT_080206d0;
  *(undefined4 *)(iVar4 + 0x20) = 5;
  return;
}

