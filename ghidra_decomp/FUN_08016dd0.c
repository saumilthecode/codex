
void FUN_08016dd0(void)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = DAT_08016df4;
  DataMemoryBarrier(0x1b);
  if ((-1 < *DAT_08016df4 << 0x1f) && (iVar2 = FUN_0801f0da(DAT_08016df4), iVar2 != 0)) {
    FUN_0801f0f2(piVar1);
    return;
  }
  return;
}

