
void FUN_0800b6cc(int param_1)

{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  uint uVar4;
  undefined1 *puVar5;
  undefined4 *puVar6;
  
  puVar5 = (undefined1 *)(param_1 + 0xc);
  iVar3 = 0;
  do {
    iVar1 = FUN_08025928(iVar3);
    if (iVar1 == -1) break;
    iVar3 = iVar3 + 1;
    puVar5 = puVar5 + 1;
    *puVar5 = (char)iVar1;
  } while (iVar3 != 0x80);
  *(bool *)(param_1 + 0xc) = iVar3 == 0x80;
  puVar6 = (undefined4 *)(param_1 + 0x8c);
  iVar3 = 0;
  do {
    uVar2 = FUN_08025804(iVar3);
    iVar3 = iVar3 + 1;
    puVar6 = puVar6 + 1;
    *puVar6 = uVar2;
  } while (iVar3 != 0x100);
  puVar5 = (undefined1 *)(param_1 + 0x48f);
  puVar6 = (undefined4 *)(param_1 + 0x49c);
  uVar4 = 0;
  do {
    puVar5 = puVar5 + 1;
    *puVar5 = (char)(1 << (uVar4 & 0xff));
    uVar2 = FUN_0800b46c(param_1);
    uVar4 = uVar4 + 1;
    puVar6 = puVar6 + 1;
    *puVar6 = uVar2;
  } while (uVar4 != 8);
  return;
}

