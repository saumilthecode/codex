
int * FUN_080176b6(int *param_1,undefined4 param_2)

{
  int iVar1;
  int *local_10;
  undefined4 uStack_c;
  
  if (*(int *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x78) != 0) {
    local_10 = param_1;
    uStack_c = param_2;
    FUN_08017700(&local_10,param_1);
    if (((char)local_10 != '\0') &&
       (iVar1 = FUN_08017c60(*(undefined4 *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x78)),
       iVar1 == -1)) {
      FUN_08010584(*(int *)(*param_1 + -0xc) + (int)param_1,1);
    }
    FUN_0801767c(&local_10);
  }
  return param_1;
}

