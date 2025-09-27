
void FUN_08000488(void)

{
  int iVar1;
  uint *puVar2;
  uint uVar3;
  
  puVar2 = DAT_080004d0;
  iVar1 = DAT_080004cc;
  *(uint *)(DAT_080004cc + 0x88) = *(uint *)(DAT_080004cc + 0x88) | 0xf00000;
  uVar3 = DAT_080004d4;
  *puVar2 = *puVar2 | 1;
  puVar2[2] = 0;
  *puVar2 = *puVar2 & 0xfef6ffff;
  puVar2[1] = uVar3;
  *puVar2 = *puVar2 & 0xfffbffff;
  puVar2[3] = 0;
  *(undefined4 *)(iVar1 + 8) = 0x8000000;
  return;
}

