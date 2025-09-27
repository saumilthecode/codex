
bool FUN_0801f004(int param_1)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  char *pcVar4;
  
  if (param_1 != 0) {
    FUN_0801f084();
    iVar2 = FUN_0801efca(param_1);
    if (iVar2 != 0) {
      FUN_08008420(*(undefined4 *)(param_1 + -0x14));
    }
  }
  iVar2 = FUN_08008438();
  iVar3 = FUN_0801efca();
  if (iVar3 == 0) goto LAB_0801f040;
  iVar3 = *(int *)(iVar2 + -0x18);
  bVar1 = false;
  while (FUN_0801f084(iVar2), bVar1) {
    FUN_0800845c();
LAB_0801f040:
    bVar1 = true;
  }
  pcVar4 = (char *)FUN_08008442(iVar3);
  if ((((*pcVar4 == 'G') && (pcVar4[1] == 'N')) && (pcVar4[2] == 'U')) &&
     (((pcVar4[3] == 'C' && (pcVar4[4] == 'C')) && ((pcVar4[5] == '+' && (pcVar4[6] == '+')))))) {
    return (byte)pcVar4[7] < 2;
  }
  return false;
}

