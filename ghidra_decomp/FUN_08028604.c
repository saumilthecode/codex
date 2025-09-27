
void FUN_08028604(void)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  
  iVar1 = DAT_0802863c - (int)DAT_08028640;
  puVar2 = DAT_08028640;
  for (iVar3 = 0; iVar3 != iVar1 >> 2; iVar3 = iVar3 + 1) {
    (*(code *)*puVar2)();
    puVar2 = puVar2 + 1;
  }
  FUN_0802f9f8();
  iVar1 = DAT_08028648 - (int)DAT_08028644;
  puVar2 = DAT_08028644;
  for (iVar3 = 0; iVar3 != iVar1 >> 2; iVar3 = iVar3 + 1) {
    (*(code *)*puVar2)();
    puVar2 = puVar2 + 1;
  }
  return;
}

