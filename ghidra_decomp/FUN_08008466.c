
void FUN_08008466(int param_1)

{
  int iVar1;
  code *pcVar2;
  
  if (param_1 == 0) {
    param_1 = 1;
  }
  while( true ) {
    iVar1 = FUN_080249b4(param_1);
    if (iVar1 != 0) {
      return;
    }
    pcVar2 = (code *)FUN_0801f0f8();
    if (pcVar2 == (code *)0x0) break;
    (*pcVar2)();
  }
                    /* WARNING: Subroutine does not return */
  FUN_080249a4();
}

