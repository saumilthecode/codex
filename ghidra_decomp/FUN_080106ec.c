
void FUN_080106ec(int param_1,undefined4 param_2)

{
  int *piVar1;
  
  for (piVar1 = *(int **)(param_1 + 0x18); piVar1 != (int *)0x0; piVar1 = (int *)*piVar1) {
    (*(code *)piVar1[1])(param_2,param_1,piVar1[2]);
  }
  return;
}

