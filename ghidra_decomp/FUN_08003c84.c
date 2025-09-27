
void FUN_08003c84(undefined4 *param_1)

{
  undefined4 uVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = (int *)param_1[0xe];
  uVar1 = FUN_0800061c();
  if (-1 < *(int *)*param_1 << 0x17) {
    iVar2 = piVar3[10];
    *(uint *)(*piVar3 + 4) = *(uint *)(*piVar3 + 4) & 0xffffffdf;
    if ((iVar2 == 0x2000) && (iVar2 = FUN_08002374(piVar3,1,1,uVar1), iVar2 != 0)) {
      piVar3[0x15] = piVar3[0x15] | 2;
    }
    iVar2 = FUN_08002434(piVar3,uVar1);
    if (iVar2 != 0) {
      piVar3[0x15] = piVar3[0x15] | 0x20;
    }
    iVar2 = *piVar3;
    *(uint *)(iVar2 + 4) = *(uint *)(iVar2 + 4) & 0xfffffffc;
    *(undefined2 *)((int)piVar3 + 0x36) = 0;
    *(undefined2 *)((int)piVar3 + 0x3e) = 0;
    *(undefined1 *)((int)piVar3 + 0x51) = 1;
    if (*(int *)(iVar2 + 8) << 0x1b < 0) {
      piVar3[0x15] = piVar3[0x15] | 2;
      *(undefined4 *)(iVar2 + 8) = 0xffef;
      iVar2 = piVar3[0x15];
    }
    else {
      iVar2 = piVar3[0x15];
    }
    if (iVar2 != 0) {
      FUN_0800363c(piVar3);
      return;
    }
  }
  FUN_08003608(piVar3);
  return;
}

