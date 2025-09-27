
void FUN_0800845c(void)

{
  int iVar1;
  int iVar2;
  code *pcVar3;
  
  FUN_0800844c();
  iVar1 = FUN_08008442();
  if (iVar1 == 0) {
    iVar1 = 1;
  }
  while( true ) {
    iVar2 = FUN_080249b4(iVar1);
    if (iVar2 != 0) {
      return;
    }
    pcVar3 = (code *)FUN_0801f0f8();
    if (pcVar3 == (code *)0x0) break;
    (*pcVar3)();
  }
                    /* WARNING: Subroutine does not return */
  FUN_080249a4();
}

