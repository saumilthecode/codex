
undefined4 FUN_0800cfb0(undefined4 param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar4;
  undefined8 uVar5;
  int *piVar3;
  
  uVar5 = CONCAT44(param_2,param_1);
  uVar1 = DAT_0800cfe0;
  if (*(int *)(param_2 + 0x18) != 0) goto LAB_0800cfbe;
  do {
    uVar5 = FUN_080104fc(uVar1);
LAB_0800cfbe:
    piVar3 = (int *)((ulonglong)uVar5 >> 0x20);
    iVar2 = *piVar3;
    iVar4 = piVar3[1];
    *(int *)uVar5 = (int)((int *)uVar5 + 2);
  } while ((iVar2 == 0) && (uVar1 = DAT_0800cfe4, iVar4 != 0));
  FUN_0800bc20(param_1,iVar2,iVar2 + iVar4 * 4);
  return param_1;
}

