
int FUN_08017a8a(int *param_1)

{
  int iVar1;
  int *piVar2;
  bool bVar3;
  
  iVar1 = (**(code **)(*param_1 + 0x24))();
  piVar2 = (int *)(iVar1 + 1);
  bVar3 = piVar2 != (int *)0x0;
  if (bVar3) {
    piVar2 = (int *)param_1[2] + 1;
    iVar1 = *(int *)param_1[2];
  }
  if (bVar3) {
    param_1[2] = (int)piVar2;
  }
  return iVar1;
}

