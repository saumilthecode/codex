
int * FUN_080177ca(int *param_1,undefined4 param_2)

{
  int iVar1;
  int *local_10;
  undefined4 uStack_c;
  
  if (*(int *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x7c) != 0) {
    local_10 = param_1;
    uStack_c = param_2;
    FUN_08017814(&local_10,param_1);
    if (((char)local_10 != '\0') &&
       (iVar1 = FUN_08017ca0(*(undefined4 *)((int)param_1 + *(int *)(*param_1 + -0xc) + 0x7c)),
       iVar1 == -1)) {
      FUN_08010648(*(int *)(*param_1 + -0xc) + (int)param_1,1);
    }
    FUN_08017790(&local_10);
  }
  return param_1;
}

