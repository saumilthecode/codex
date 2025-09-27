
void FUN_08000794(uint param_1,uint param_2,uint param_3)

{
  undefined1 uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar2 = (uint)(*(int *)(DAT_08000804 + 0xc) << 0x15) >> 0x1d;
  uVar3 = 7 - uVar2;
  if (3 < uVar3) {
    uVar3 = 4;
  }
  if (uVar2 + 4 < 7) {
    param_3 = 0;
    uVar2 = param_3;
  }
  else {
    param_3 = param_3 & ~(-1 << (uVar2 - 3 & 0xff));
    uVar2 = uVar2 - 3;
  }
  uVar1 = (undefined1)
          ((((param_2 & ~(-1 << (uVar3 & 0xff))) << (uVar2 & 0xff) | param_3) & 0xf) << 4);
  if (-1 < (int)param_1) {
    *(undefined1 *)(param_1 + 0xe000e400) = uVar1;
    return;
  }
  *(undefined1 *)(DAT_08000808 + (param_1 & 0xf) + 0x18) = uVar1;
  return;
}

