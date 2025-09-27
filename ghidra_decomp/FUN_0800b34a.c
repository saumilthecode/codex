
void FUN_0800b34a(int *param_1)

{
  undefined1 uVar1;
  undefined1 *puVar2;
  int iVar3;
  undefined1 auStack_118 [256];
  undefined1 auStack_18 [4];
  
  iVar3 = 0;
  puVar2 = auStack_118;
  do {
    *puVar2 = (char)iVar3;
    iVar3 = iVar3 + 1;
    puVar2 = puVar2 + 1;
  } while (iVar3 != 0x100);
  (**(code **)(*param_1 + 0x1c))(param_1,auStack_118,auStack_18);
  iVar3 = FUN_080268d0(auStack_118,(int)param_1 + 0x1d,0x100);
  if (iVar3 == 0) {
    uVar1 = 1;
  }
  else {
    uVar1 = 2;
  }
  *(undefined1 *)(param_1 + 7) = uVar1;
  return;
}

