.class public final enum Llyiahf/vczjk/tu9;
.super Llyiahf/vczjk/rw9;
.source "SourceFile"


# direct methods
.method public constructor <init>()V
    .locals 2

    const-string v0, "ScriptDataEscapedEndTagOpen"

    const/16 v1, 0x19

    invoke-direct {p0, v0, v1}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    return-void
.end method


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/bu9;Llyiahf/vczjk/zt0;)V
    .locals 2

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooOOOO()Z

    move-result v0

    if-eqz v0, :cond_0

    const/4 v0, 0x0

    invoke-virtual {p1, v0}, Llyiahf/vczjk/bu9;->OooO0Oo(Z)Llyiahf/vczjk/pt9;

    iget-object v0, p1, Llyiahf/vczjk/bu9;->OooO:Llyiahf/vczjk/pt9;

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO()C

    move-result v1

    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    invoke-static {v1}, Ljava/lang/String;->valueOf(C)Ljava/lang/String;

    move-result-object v1

    invoke-virtual {v0, v1}, Llyiahf/vczjk/pt9;->OooOOo0(Ljava/lang/String;)V

    iget-object v0, p1, Llyiahf/vczjk/bu9;->OooO0oo:Ljava/lang/StringBuilder;

    invoke-virtual {p2}, Llyiahf/vczjk/zt0;->OooO()C

    move-result p2

    invoke-virtual {v0, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    sget-object p2, Llyiahf/vczjk/rw9;->Oooo0o0:Llyiahf/vczjk/uu9;

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO00o(Llyiahf/vczjk/rw9;)V

    return-void

    :cond_0
    const-string p2, "</"

    invoke-virtual {p1, p2}, Llyiahf/vczjk/bu9;->OooO0oO(Ljava/lang/String;)V

    sget-object p2, Llyiahf/vczjk/rw9;->Oooo00O:Llyiahf/vczjk/pu9;

    iput-object p2, p1, Llyiahf/vczjk/bu9;->OooO0OO:Llyiahf/vczjk/rw9;

    return-void
.end method
