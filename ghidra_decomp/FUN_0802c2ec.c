
int FUN_0802c2ec(undefined4 param_1,int param_2,int param_3)

{
  int iVar1;
  undefined1 *puVar2;
  undefined1 auStack_1c [4];
  
  iVar1 = (int)*(short *)(param_3 + 0xc);
  if ((-1 < *(int *)(param_3 + 100) << 0x1f) && (-1 < iVar1 << 0x16)) {
    FUN_08028650(*(undefined4 *)(param_3 + 0x58));
    iVar1 = (int)*(short *)(param_3 + 0xc);
  }
  if (-1 < iVar1 << 0x12) {
    *(ushort *)(param_3 + 0xc) = (ushort)iVar1 | 0x2000;
    *(uint *)(param_3 + 100) = *(uint *)(param_3 + 100) | 0x2000;
  }
  if (param_2 != -1) {
    iVar1 = FUN_080258e8(param_1,auStack_1c,param_2,param_3 + 0x5c);
    if (iVar1 == -1) {
      *(ushort *)(param_3 + 0xc) = *(ushort *)(param_3 + 0xc) | 0x40;
    }
    else {
      puVar2 = auStack_1c + iVar1;
      do {
        if (auStack_1c == puVar2) goto LAB_0802c34c;
        puVar2 = puVar2 + -1;
        iVar1 = FUN_0802643c(param_1,*puVar2,param_3);
      } while (iVar1 != -1);
    }
  }
  param_2 = -1;
LAB_0802c34c:
  if ((-1 < *(int *)(param_3 + 100) << 0x1f) &&
     (-1 < (int)((uint)*(ushort *)(param_3 + 0xc) << 0x16))) {
    FUN_08028654(*(undefined4 *)(param_3 + 0x58));
    return param_2;
  }
  return param_2;
}

