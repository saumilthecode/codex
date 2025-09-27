
undefined4 FUN_08002214(int *param_1,uint param_2,uint param_3,int param_4,int param_5)

{
  int iVar1;
  int iVar2;
  uint *puVar3;
  uint uVar4;
  int local_24;
  
  iVar1 = FUN_0800061c();
  uVar4 = (param_5 + param_4) - iVar1;
  iVar1 = FUN_0800061c();
  local_24 = uVar4 * ((uint)(*DAT_080022e8 << 5) >> 0x14);
  if (param_4 == -1) {
    do {
    } while (((param_2 & ~*(uint *)(*param_1 + 8)) == 0) != param_3);
  }
  else {
    while (((param_2 & ~*(uint *)(*param_1 + 8)) == 0) != param_3) {
      iVar2 = FUN_0800061c();
      if (uVar4 <= (uint)(iVar2 - iVar1)) {
        puVar3 = (uint *)*param_1;
        iVar1 = param_1[1];
        puVar3[1] = puVar3[1] & 0xffffff1f;
        if ((iVar1 == 0x104) && ((param_1[2] == 0x8000 || (param_1[2] == 0x400)))) {
          *puVar3 = *puVar3 & 0xffffffbf;
        }
        if (param_1[10] == 0x2000) {
          *puVar3 = *puVar3 & 0xffffdfff;
          *puVar3 = *puVar3 | 0x2000;
        }
        *(undefined1 *)((int)param_1 + 0x51) = 1;
        *(undefined1 *)(param_1 + 0x14) = 0;
        return 3;
      }
      if (local_24 == 0) {
        uVar4 = 0;
      }
      else {
        local_24 = local_24 + -1;
      }
    }
  }
  return 0;
}

