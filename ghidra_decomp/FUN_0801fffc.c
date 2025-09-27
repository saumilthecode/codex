
void FUN_0801fffc(int param_1)

{
  undefined4 uVar1;
  byte *pbVar2;
  uint *puVar3;
  undefined4 *puVar4;
  int iVar5;
  
  puVar4 = *(undefined4 **)(param_1 + 8);
  if (puVar4 == (undefined4 *)0x0) {
    puVar4 = (undefined4 *)FUN_08008466(0x70);
    puVar4[2] = 0;
    puVar4[3] = 0;
    puVar4[5] = 0;
    puVar4[6] = 0;
    puVar4[7] = 0;
    puVar4[8] = 0;
    puVar4[9] = 0;
    puVar4[10] = 0;
    puVar4[0xb] = 0;
    puVar4[0xc] = 0;
    puVar4[0xd] = 0;
    puVar4[0xe] = 0;
    uVar1 = DAT_0802007c;
    puVar4[1] = 0;
    *puVar4 = uVar1;
    *(undefined1 *)(puVar4 + 4) = 0;
    puVar4[0xf] = 0;
    *(undefined1 *)(puVar4 + 0x1b) = 0;
    *(undefined4 **)(param_1 + 8) = puVar4;
  }
  puVar4[5] = 0x2e;
  puVar4[6] = 0x2c;
  uVar1 = DAT_08020080;
  puVar4[2] = DAT_08020084;
  puVar4[7] = uVar1;
  puVar4[8] = 0;
  puVar4[9] = uVar1;
  puVar4[10] = 0;
  puVar4[0xb] = uVar1;
  puVar4[0xc] = 0;
  puVar4[3] = 0;
  puVar4[0xd] = 0;
  uVar1 = *DAT_08020088;
  puVar4[0xe] = uVar1;
  *(undefined4 *)(*(int *)(param_1 + 8) + 0x3c) = uVar1;
  iVar5 = *DAT_0802008c;
  puVar3 = (uint *)(*(int *)(param_1 + 8) + 0x3c);
  pbVar2 = (byte *)(iVar5 + -1);
  do {
    pbVar2 = pbVar2 + 1;
    puVar3 = puVar3 + 1;
    *puVar3 = (uint)*pbVar2;
  } while (pbVar2 != (byte *)(iVar5 + 10));
  return;
}

