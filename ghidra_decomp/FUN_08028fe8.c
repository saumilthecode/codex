
void FUN_08028fe8(int param_1,undefined4 *param_2)

{
  undefined4 *puVar1;
  int iVar2;
  
  if (*(int *)(param_1 + 0x1c) == 0) {
    puVar1 = (undefined4 *)FUN_080249b4(0x10);
    *(undefined4 **)(param_1 + 0x1c) = puVar1;
    if (puVar1 == (undefined4 *)0x0) {
      puVar1 = (undefined4 *)FUN_08028754(DAT_08029028,0x8f,0,DAT_08029024);
    }
    puVar1[1] = 0;
    puVar1[2] = 0;
    *puVar1 = 0;
    puVar1[3] = 0;
  }
  if (param_2 != (undefined4 *)0x0) {
    iVar2 = *(int *)(*(int *)(param_1 + 0x1c) + 0xc);
    *param_2 = *(undefined4 *)(iVar2 + param_2[1] * 4);
    *(undefined4 **)(iVar2 + param_2[1] * 4) = param_2;
  }
  return;
}

