
int * FUN_08017594(int *param_1)

{
  int iVar1;
  int iVar2;
  int *piVar3;
  
  *param_1 = 0;
  piVar3 = DAT_080175c0;
  FUN_08017584();
  iVar2 = *piVar3;
  iVar1 = *DAT_080175c4;
  *param_1 = iVar2;
  if (iVar2 != iVar1) {
    FUN_08016dd0();
    piVar3 = (int *)*piVar3;
    *param_1 = (int)piVar3;
    *piVar3 = *piVar3 + 1;
  }
  return param_1;
}

