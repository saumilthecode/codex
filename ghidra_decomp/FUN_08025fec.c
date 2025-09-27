
uint FUN_08025fec(undefined4 param_1,code *param_2,int *param_3)

{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  uVar3 = 0;
  do {
    iVar4 = param_3[1];
    iVar2 = param_3[2];
    while (iVar4 = iVar4 + -1, -1 < iVar4) {
      if ((1 < *(ushort *)(iVar2 + 0xc)) && (*(short *)(iVar2 + 0xe) != -1)) {
        uVar1 = (*param_2)(param_1,iVar2);
        uVar3 = uVar3 | uVar1;
      }
      iVar2 = iVar2 + 0x68;
    }
    param_3 = (int *)*param_3;
  } while (param_3 != (int *)0x0);
  return uVar3;
}

