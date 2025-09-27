
uint FUN_0801fa78(int param_1,int param_2,int param_3)

{
  int iVar1;
  int iVar2;
  
  iVar1 = param_1 + 0x76c;
  if (param_2 < 2) {
    iVar1 = param_1 + 0x76b;
  }
  iVar2 = iVar1;
  if (iVar1 < 0) {
    iVar2 = iVar1 + 3;
  }
  return ((int)((((param_1 + -0x46) * 0x16d + (iVar2 >> 2) + iVar1 / -100) -
                ((iVar2 >> 2) % 0x19 >> 0x1f)) + iVar1 / 400 +
                (uint)*(ushort *)(DAT_0801faec + param_2 * 2) + param_3 + -0x1da) % 7 + 7U) % 7;
}

