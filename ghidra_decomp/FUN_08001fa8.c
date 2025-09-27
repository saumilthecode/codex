
undefined4 FUN_08001fa8(undefined4 *param_1)

{
  if (param_1 != (undefined4 *)0x0) {
    if (*(char *)((int)param_1 + 5) == '\0') {
      *(undefined1 *)(param_1 + 1) = 0;
      FUN_08001fa4();
    }
    *(undefined1 *)((int)param_1 + 5) = 2;
    *(uint *)*param_1 = *(uint *)*param_1 | 4;
    *(undefined1 *)((int)param_1 + 5) = 1;
    param_1[2] = 0;
    return 0;
  }
  return 1;
}

