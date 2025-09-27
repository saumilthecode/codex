
undefined4 FUN_08004328(int *param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  uint uVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  uint uVar5;
  int iVar6;
  bool bVar7;
  
  if (param_1 != (int *)0x0) {
    if (*(char *)((int)param_1 + 0x41) == '\0') {
      *(undefined1 *)(param_1 + 0x10) = 0;
      FUN_08004324();
    }
    iVar6 = *param_1;
    uVar1 = param_1[3];
    *(undefined1 *)((int)param_1 + 0x41) = 0x24;
    *(uint *)(iVar6 + 0xc) = *(uint *)(iVar6 + 0xc) & 0xffffdfff;
    uVar5 = param_1[2];
    uVar2 = param_1[4];
    *(uint *)(iVar6 + 0x10) = *(uint *)(iVar6 + 0x10) & 0xffffcfff | uVar1;
    *(uint *)(iVar6 + 0xc) =
         uVar5 | uVar2 | param_1[5] | param_1[7] | *(uint *)(iVar6 + 0xc) & 0xffff69f3;
    bVar7 = iVar6 == DAT_08004440;
    *(uint *)(iVar6 + 0x14) = *(uint *)(iVar6 + 0x14) & 0xfffffcff | param_1[6];
    if ((bVar7) || (iVar6 == DAT_08004444)) {
      uVar1 = FUN_08001e98();
    }
    else {
      uVar1 = FUN_08001e78();
    }
    iVar6 = *param_1;
    uVar2 = param_1[1];
    uVar3 = (undefined4)((ulonglong)uVar1 * 0x19);
    uVar4 = (undefined4)((ulonglong)uVar1 * 0x19 >> 0x20);
    if (param_1[7] == 0x8000) {
      uVar1 = FUN_08006980(uVar3,uVar4,uVar2 * 2,CARRY4(uVar2,uVar2),param_4);
      uVar2 = (uint)((ulonglong)DAT_08004448 * (ulonglong)uVar1 >> 0x25);
      uVar1 = (uint)((ulonglong)DAT_08004448 * (ulonglong)((uVar1 + uVar2 * -100) * 8 + 0x32) >>
                    0x20);
      *(uint *)(iVar6 + 8) = (uVar1 >> 4 & 0x1f0) + ((uVar1 << 0x18) >> 0x1d) + uVar2 * 0x10;
    }
    else {
      uVar1 = FUN_08006980(uVar3,uVar4,uVar2 << 2,uVar2 >> 0x1e,param_4);
      uVar2 = (uint)((ulonglong)DAT_08004448 * (ulonglong)uVar1 >> 0x25);
      *(uint *)(iVar6 + 8) =
           uVar2 * 0x10 +
           (uint)((ulonglong)DAT_08004448 * (ulonglong)((uVar1 + uVar2 * -100) * 0x10 + 0x32) >>
                 0x25);
    }
    *(uint *)(iVar6 + 0x10) = *(uint *)(iVar6 + 0x10) & 0xffffb7ff;
    *(uint *)(iVar6 + 0x14) = *(uint *)(iVar6 + 0x14) & 0xffffffd5;
    *(uint *)(iVar6 + 0xc) = *(uint *)(iVar6 + 0xc) | 0x2000;
    param_1[0x11] = 0;
    *(undefined1 *)((int)param_1 + 0x41) = 0x20;
    *(undefined1 *)((int)param_1 + 0x42) = 0x20;
    param_1[0xd] = 0;
    return 0;
  }
  return 1;
}

