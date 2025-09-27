
undefined4 FUN_0802b67a(int param_1,int param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  if (param_2 == 0) {
    return 0;
  }
  iVar3 = 0;
  iVar2 = param_2 + -1;
  do {
    while( true ) {
      iVar1 = (iVar3 + iVar2) / 2;
      uVar4 = FUN_0802b668(param_1 + iVar1 * 8);
      if (param_2 + -1 == iVar1) break;
      if (param_3 < (uint)uVar4) goto LAB_0802b6ac;
      uVar4 = FUN_0802b668(iVar1 * 8 + 8 + param_1);
      if (param_3 <= (int)uVar4 - 1U) {
        return (int)((ulonglong)uVar4 >> 0x20);
      }
      iVar3 = iVar1 + 1;
    }
    if ((uint)uVar4 <= param_3) {
      return (int)((ulonglong)uVar4 >> 0x20);
    }
LAB_0802b6ac:
    if (iVar3 == iVar1) {
      return 0;
    }
    iVar2 = iVar1 + -1;
  } while( true );
}

