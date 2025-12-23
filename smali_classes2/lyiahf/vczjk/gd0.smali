.class public abstract Llyiahf/vczjk/gd0;
.super Llyiahf/vczjk/ak1;
.source "SourceFile"


# virtual methods
.method public final OooO0Oo()Llyiahf/vczjk/ak1;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/ak1;->OooO0O0:Ljava/lang/Object;

    check-cast v0, Llyiahf/vczjk/ak1;

    check-cast v0, Llyiahf/vczjk/gd0;

    return-object v0
.end method

.method public final OooO0oo(Llyiahf/vczjk/ak1;)V
    .locals 1

    instance-of v0, p1, Llyiahf/vczjk/gd0;

    if-eqz v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/ak1;->OooO0O0:Ljava/lang/Object;

    return-void

    :cond_0
    new-instance p1, Ljava/lang/IllegalArgumentException;

    const-string v0, "Parent of block must also be block (can not be inline)"

    invoke-direct {p1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p1
.end method
