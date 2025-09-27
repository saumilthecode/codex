
int * FUN_0801796c(int *param_1,undefined4 param_2)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  char local_30 [8];
  undefined4 local_28;
  undefined4 uStack_24;
  undefined1 auStack_20 [4];
  char local_1c;
  
  FUN_08017700(local_30,param_1);
  if (local_30[0] != '\0') {
    iVar2 = *(int *)(*param_1 + -0xc) + (int)param_1;
    iVar3 = *(int *)(iVar2 + 0x80);
    if (iVar3 == 0) {
      FUN_080104f6();
    }
    FUN_08017956(&local_28,param_1);
    uVar1 = FUN_080105ba(iVar2);
    FUN_08010d54(auStack_20,iVar3,local_28,uStack_24,iVar2,uVar1,param_2);
    if (local_1c != '\0') {
      FUN_08010584(*(int *)(*param_1 + -0xc) + (int)param_1,1);
    }
  }
  FUN_0801767c(local_30);
  return param_1;
}

