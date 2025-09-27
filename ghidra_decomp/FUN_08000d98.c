
undefined4 FUN_08000d98(undefined4 *param_1)

{
  if (*(char *)((int)param_1 + 0x35) != '\x02') {
    param_1[0x15] = 0x80;
    return 1;
  }
  *(undefined1 *)((int)param_1 + 0x35) = 5;
  *(uint *)*param_1 = *(uint *)*param_1 & 0xfffffffe;
  return 0;
}

