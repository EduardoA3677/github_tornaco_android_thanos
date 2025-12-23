.class public abstract Llyiahf/vczjk/fx4;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/tx6;


# instance fields
.field public OooO00o:Llyiahf/vczjk/cx4;


# virtual methods
.method public final OooO(Llyiahf/vczjk/cx4;)V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    if-ne v0, p1, :cond_0

    goto :goto_0

    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    const-string v1, "Expected textInputModifierNode to be "

    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    const-string p1, " but was "

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    iget-object p1, p0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    invoke-virtual {v0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object p1

    invoke-static {p1}, Llyiahf/vczjk/sz3;->OooO0OO(Ljava/lang/String;)V

    :goto_0
    const/4 p1, 0x0

    iput-object p1, p0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    return-void
.end method

.method public final OooO0Oo()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    if-eqz v0, :cond_0

    sget-object v1, Llyiahf/vczjk/ch1;->OooOOOo:Llyiahf/vczjk/l39;

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dx8;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/q52;

    invoke-virtual {v0}, Llyiahf/vczjk/q52;->OooO0O0()V

    :cond_0
    return-void
.end method

.method public final OooO0oO()V
    .locals 2

    iget-object v0, p0, Llyiahf/vczjk/fx4;->OooO00o:Llyiahf/vczjk/cx4;

    if-eqz v0, :cond_0

    sget-object v1, Llyiahf/vczjk/ch1;->OooOOOo:Llyiahf/vczjk/l39;

    invoke-static {v0, v1}, Llyiahf/vczjk/t51;->OooOo(Llyiahf/vczjk/ug1;Landroidx/compose/runtime/OooO;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/dx8;

    if-eqz v0, :cond_0

    check-cast v0, Llyiahf/vczjk/q52;

    invoke-virtual {v0}, Llyiahf/vczjk/q52;->OooO00o()V

    :cond_0
    return-void
.end method
