
undefined4 FUN_08000d04(undefined4 *param_1)

{
  int iVar1;
  int iVar2;
  uint *puVar3;
  int iVar4;
  
  iVar4 = param_1[0x16];
  iVar1 = FUN_0800061c();
  if (*(char *)((int)param_1 + 0x35) != '\x02') {
    param_1[0x15] = 0x80;
    *(undefined1 *)(param_1 + 0xd) = 0;
    return 1;
  }
  puVar3 = (uint *)*param_1;
  *puVar3 = *puVar3 & 0xffffffe9;
  puVar3[5] = puVar3[5] & 0xffffff7f;
  if ((param_1[0x10] != 0) || (param_1[0x12] != 0)) {
    *puVar3 = *puVar3 & 0xfffffff7;
  }
  *puVar3 = *puVar3 & 0xfffffffe;
  while( true ) {
    if ((*puVar3 & 1) == 0) {
      *(int *)(iVar4 + 8) = 0x3f << (param_1[0x17] & 0xff);
      *(undefined1 *)((int)param_1 + 0x35) = 1;
      *(undefined1 *)(param_1 + 0xd) = 0;
      return 0;
    }
    iVar2 = FUN_0800061c();
    if (5 < (uint)(iVar2 - iVar1)) break;
    puVar3 = (uint *)*param_1;
  }
  param_1[0x15] = 0x20;
  *(undefined1 *)((int)param_1 + 0x35) = 3;
  *(undefined1 *)(param_1 + 0xd) = 0;
  return 3;
}

