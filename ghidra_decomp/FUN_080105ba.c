
undefined1 FUN_080105ba(int param_1)

{
  undefined1 uVar1;
  
  if (*(char *)(param_1 + 0x75) == '\0') {
    uVar1 = FUN_08010590(param_1,0x20);
    *(undefined1 *)(param_1 + 0x74) = uVar1;
    *(undefined1 *)(param_1 + 0x75) = 1;
  }
  return *(undefined1 *)(param_1 + 0x74);
}

