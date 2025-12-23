.class public final Llyiahf/vczjk/w58;
.super Llyiahf/vczjk/tr5;
.source "SourceFile"


# instance fields
.field public OooOO0o:Ljava/lang/String;

.field public OooOOO0:Llyiahf/vczjk/x58;


# virtual methods
.method public final OooO(Ljava/lang/Object;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/w58;->OooOOO0:Llyiahf/vczjk/x58;

    if-eqz v0, :cond_0

    iget-object v0, v0, Llyiahf/vczjk/x58;->OooO0O0:Llyiahf/vczjk/mi;

    if-eqz v0, :cond_0

    iget-object v1, p0, Llyiahf/vczjk/w58;->OooOO0o:Ljava/lang/String;

    invoke-virtual {v0, p1, v1}, Llyiahf/vczjk/mi;->Oooo0oo(Ljava/lang/Object;Ljava/lang/String;)V

    :cond_0
    invoke-super {p0, p1}, Llyiahf/vczjk/tr5;->OooO(Ljava/lang/Object;)V

    return-void
.end method
