
undefined4 FUN_080031f0(int *param_1,int param_2,int param_3,int param_4)

{
  undefined2 uVar1;
  undefined4 uVar2;
  int iVar3;
  uint *puVar4;
  int iVar5;
  int iVar6;
  undefined4 uVar7;
  
  if ((*(char *)((int)param_1 + 0x51) != '\x01') &&
     (((param_1[1] != 0x104 || (param_1[2] != 0)) || (*(char *)((int)param_1 + 0x51) != '\x04')))) {
    return 2;
  }
  if (((param_2 != 0) && (param_3 != 0)) && (param_4 != 0)) {
    if ((char)param_1[0x14] == '\x01') {
      return 2;
    }
    *(undefined1 *)(param_1 + 0x14) = 1;
    uVar1 = (undefined2)param_4;
    *(undefined2 *)(param_1 + 0xd) = uVar1;
    if (*(char *)((int)param_1 + 0x51) != '\x04') {
      *(undefined1 *)((int)param_1 + 0x51) = 5;
    }
    param_1[0x15] = 0;
    *(undefined2 *)(param_1 + 0xf) = uVar1;
    *(undefined2 *)((int)param_1 + 0x36) = uVar1;
    *(undefined2 *)((int)param_1 + 0x3e) = uVar1;
    param_1[0xc] = param_2;
    param_1[0x10] = 0;
    param_1[0x11] = 0;
    puVar4 = (uint *)*param_1;
    param_1[0xe] = param_3;
    if (param_1[10] == 0x2000) {
      *puVar4 = *puVar4 & 0xffffdfff;
      *puVar4 = *puVar4 | 0x2000;
    }
    iVar3 = param_1[0x13];
    uVar7 = DAT_08003308;
    uVar2 = DAT_08003304;
    if (*(char *)((int)param_1 + 0x51) == '\x04') {
      uVar7 = DAT_08003310;
      uVar2 = DAT_0800330c;
    }
    *(undefined4 *)(iVar3 + 0x3c) = uVar7;
    *(undefined4 *)(iVar3 + 0x40) = uVar2;
    *(undefined4 *)(iVar3 + 0x4c) = DAT_08003314;
    uVar1 = *(undefined2 *)((int)param_1 + 0x3e);
    *(undefined4 *)(iVar3 + 0x50) = 0;
    iVar3 = FUN_08000c8c(iVar3,puVar4 + 3,param_3,uVar1);
    if (iVar3 == 0) {
      iVar6 = *param_1;
      iVar3 = param_1[0x12];
      iVar5 = param_1[0xc];
      *(uint *)(iVar6 + 4) = *(uint *)(iVar6 + 4) | 1;
      uVar1 = *(undefined2 *)((int)param_1 + 0x36);
      *(undefined4 *)(iVar3 + 0x3c) = 0;
      *(undefined4 *)(iVar3 + 0x40) = 0;
      *(undefined4 *)(iVar3 + 0x4c) = 0;
      *(undefined4 *)(iVar3 + 0x50) = 0;
      iVar3 = FUN_08000c8c(iVar3,iVar5,iVar6 + 0xc,uVar1);
      if (iVar3 == 0) {
        puVar4 = (uint *)*param_1;
        if (-1 < (int)(*puVar4 << 0x19)) {
          *puVar4 = *puVar4 | 0x40;
        }
        *(undefined1 *)(param_1 + 0x14) = 0;
        puVar4[1] = puVar4[1] | 0x20;
        puVar4[1] = puVar4[1] | 2;
        return 0;
      }
      *(undefined1 *)(param_1 + 0x14) = 0;
      param_1[0x15] = param_1[0x15] | 0x10;
    }
    else {
      *(undefined1 *)(param_1 + 0x14) = 0;
      param_1[0x15] = param_1[0x15] | 0x10;
    }
  }
  return 1;
}

