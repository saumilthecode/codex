
void FUN_080105fe(int param_1,int param_2)

{
  FUN_0801fa22();
  FUN_080105da(param_1,param_1 + 0x6c);
  *(int *)(param_1 + 0x78) = param_2;
  *(undefined2 *)(param_1 + 0x74) = 0;
  *(undefined4 *)(param_1 + 0x70) = 0;
  *(undefined4 *)(param_1 + 0x10) = 0;
  *(uint *)(param_1 + 0x14) = (uint)(param_2 == 0);
  return;
}

