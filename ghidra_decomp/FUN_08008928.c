
void FUN_08008928(void)

{
  int *piVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 in_r3;
  
  uVar2 = DAT_0800893c;
  piVar1 = DAT_08008938;
  if (*DAT_08008938 == 0) {
    *DAT_08008938 = 0;
    iVar3 = FUN_08005de4(uVar2,DAT_0801f730,0,piVar1,in_r3);
    if (iVar3 != 0) {
      FUN_08010510(DAT_0801f734);
    }
    return;
  }
  return;
}

