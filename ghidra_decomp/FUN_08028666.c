
void FUN_08028666(int param_1,undefined1 *param_2,int param_3)

{
  undefined1 *puVar1;
  undefined1 *puVar2;
  undefined1 *puVar3;
  
  puVar2 = param_2 + param_3;
  puVar3 = (undefined1 *)(param_1 + -1);
  if (param_2 != puVar2) {
    do {
      puVar1 = param_2 + 1;
      puVar3 = puVar3 + 1;
      *puVar3 = *param_2;
      param_2 = puVar1;
    } while (puVar1 != puVar2);
    return;
  }
  return;
}

