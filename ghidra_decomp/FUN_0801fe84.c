
void FUN_0801fe84(int param_1)

{
  undefined1 *puVar1;
  undefined4 *puVar2;
  undefined4 uVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  
  puVar2 = *(undefined4 **)(param_1 + 8);
  if (puVar2 == (undefined4 *)0x0) {
    puVar2 = (undefined4 *)FUN_08008466(0x44);
    puVar2[2] = 0;
    puVar2[3] = 0;
    puVar2[5] = 0;
    puVar2[6] = 0;
    puVar2[7] = 0;
    puVar2[8] = 0;
    puVar2[9] = 0;
    puVar2[10] = 0;
    puVar2[0xb] = 0;
    puVar2[0xc] = 0;
    uVar3 = DAT_0801fefc;
    puVar2[1] = 0;
    *puVar2 = uVar3;
    *(undefined2 *)(puVar2 + 4) = 0;
    *(undefined1 *)((int)puVar2 + 0x12) = 0;
    puVar2[0xd] = 0;
    *(undefined1 *)((int)puVar2 + 0x43) = 0;
    *(undefined4 **)(param_1 + 8) = puVar2;
  }
  *(undefined1 *)((int)puVar2 + 0x11) = 0x2e;
  uVar3 = DAT_0801ff00;
  *(undefined1 *)(*(int *)(param_1 + 8) + 0x12) = 0x2c;
  iVar4 = *(int *)(param_1 + 8);
  iVar6 = 0;
  *(undefined4 *)(iVar4 + 0x14) = uVar3;
  *(undefined4 *)(iVar4 + 0x18) = 0;
  *(undefined4 *)(iVar4 + 0x1c) = uVar3;
  *(undefined4 *)(iVar4 + 0x20) = 0;
  *(undefined4 *)(iVar4 + 0x24) = uVar3;
  *(undefined4 *)(iVar4 + 0x28) = 0;
  *(undefined4 *)(iVar4 + 8) = uVar3;
  puVar2 = DAT_0801ff04;
  *(undefined4 *)(iVar4 + 0xc) = 0;
  uVar3 = *puVar2;
  *(undefined4 *)(iVar4 + 0x30) = uVar3;
  *(undefined4 *)(iVar4 + 0x2c) = 0;
  *(undefined4 *)(*(int *)(param_1 + 8) + 0x34) = uVar3;
  iVar4 = *DAT_0801ff08;
  do {
    puVar1 = (undefined1 *)(iVar4 + iVar6);
    iVar5 = *(int *)(param_1 + 8) + iVar6;
    iVar6 = iVar6 + 1;
    *(undefined1 *)(iVar5 + 0x38) = *puVar1;
  } while (iVar6 != 0xb);
  return;
}

