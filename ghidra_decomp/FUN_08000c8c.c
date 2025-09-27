
undefined4 FUN_08000c8c(undefined4 *param_1,uint param_2,uint param_3,uint param_4)

{
  uint uVar1;
  uint *puVar2;
  int iVar3;
  bool bVar4;
  
  iVar3 = param_1[0x16];
  if (*(char *)(param_1 + 0xd) != '\x01') {
    *(undefined1 *)(param_1 + 0xd) = 1;
    if (*(char *)((int)param_1 + 0x35) == '\x01') {
      *(undefined1 *)((int)param_1 + 0x35) = 2;
      puVar2 = (uint *)*param_1;
      param_1[0x15] = 0;
      *puVar2 = *puVar2 & 0xfffbffff;
      puVar2[1] = param_4;
      bVar4 = param_1[2] == 0x40;
      if (bVar4) {
        puVar2[2] = param_3;
      }
      if (!bVar4) {
        puVar2[2] = param_2;
      }
      if (!bVar4) {
        puVar2[3] = param_3;
      }
      uVar1 = param_1[0x17];
      if (bVar4) {
        puVar2[3] = param_2;
      }
      *(int *)(iVar3 + 8) = 0x3f << (uVar1 & 0xff);
      iVar3 = param_1[0x10];
      *puVar2 = *puVar2 | 0x16;
      if (iVar3 != 0) {
        *puVar2 = *puVar2 | 8;
      }
      *puVar2 = *puVar2 | 1;
      return 0;
    }
    *(undefined1 *)(param_1 + 0xd) = 0;
  }
  return 2;
}

