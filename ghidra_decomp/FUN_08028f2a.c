
int FUN_08028f2a(int param_1,int param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  
  if (param_3 == 0) {
    iVar2 = 0;
  }
  else {
    iVar2 = 0;
    do {
      bVar1 = *(byte *)(param_2 + iVar2);
      *(uint *)(param_1 + iVar2 * 4) = (uint)bVar1;
      if (bVar1 == 0) {
        return iVar2;
      }
      iVar2 = iVar2 + 1;
    } while (iVar2 != param_3);
  }
  return iVar2;
}

