
undefined4 FUN_080210e4(int *param_1,int param_2)

{
  undefined1 uVar1;
  undefined2 *puVar2;
  
  if (param_2 << 0x1e < 0) {
    puVar2 = (undefined2 *)*param_1;
    if ((uint)(param_1[1] - (int)puVar2) < 3) {
      return 0;
    }
    uVar1 = *(undefined1 *)(DAT_0802110c + 1);
    *puVar2 = *DAT_0802110c;
    *(undefined1 *)(puVar2 + 1) = uVar1;
    *param_1 = *param_1 + 3;
  }
  return 1;
}

