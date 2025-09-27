
void FUN_08020564(int param_1)

{
  undefined4 uVar1;
  byte *pbVar2;
  uint *puVar3;
  int iVar4;
  undefined4 *puVar5;
  
  puVar5 = *(undefined4 **)(param_1 + 8);
  if (puVar5 == (undefined4 *)0x0) {
    puVar5 = (undefined4 *)FUN_08008466(0x128);
    puVar5[2] = 0;
    puVar5[3] = 0;
    puVar5[5] = 0;
    puVar5[6] = 0;
    puVar5[7] = 0;
    puVar5[8] = 0;
    puVar5[9] = 0;
    puVar5[10] = 0;
    uVar1 = DAT_080205ec;
    puVar5[1] = 0;
    *puVar5 = uVar1;
    *(undefined1 *)(puVar5 + 4) = 0;
    *(undefined1 *)(puVar5 + 0x49) = 0;
    *(undefined4 **)(param_1 + 8) = puVar5;
  }
  puVar5[2] = DAT_080205f0;
  puVar5[3] = 0;
  *(undefined1 *)(puVar5 + 4) = 0;
  puVar5[9] = 0x2e;
  puVar3 = puVar5 + 10;
  *puVar3 = 0x2c;
  iVar4 = *DAT_080205f4;
  pbVar2 = (byte *)(iVar4 + -1);
  do {
    pbVar2 = pbVar2 + 1;
    puVar3 = puVar3 + 1;
    *puVar3 = (uint)*pbVar2;
  } while (pbVar2 != (byte *)(iVar4 + 0x23));
  iVar4 = *DAT_080205f8;
  puVar3 = puVar5 + 0x2e;
  pbVar2 = (byte *)(iVar4 + -1);
  do {
    pbVar2 = pbVar2 + 1;
    puVar3 = puVar3 + 1;
    *puVar3 = (uint)*pbVar2;
  } while (pbVar2 != (byte *)(iVar4 + 0x19));
  puVar5[5] = DAT_080205fc;
  puVar5[6] = 4;
  puVar5[7] = DAT_08020600;
  puVar5[8] = 5;
  return;
}

