
int FUN_0801767c(int param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  piVar3 = *(int **)(param_1 + 4);
  iVar2 = *(int *)(*piVar3 + -0xc);
  if ((((*(int *)((int)piVar3 + iVar2 + 0xc) << 0x12 < 0) && (iVar1 = FUN_0801f0d6(), iVar1 == 0))
      && (*(int *)((int)piVar3 + iVar2 + 0x78) != 0)) && (iVar2 = FUN_08017c60(), iVar2 == -1)) {
    piVar3 = *(int **)(param_1 + 4);
    FUN_08010584(*(int *)(*piVar3 + -0xc) + (int)piVar3,1,*piVar3,piVar3,param_4);
  }
  return param_1;
}

