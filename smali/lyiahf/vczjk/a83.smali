.class public final Llyiahf/vczjk/a83;
.super Llyiahf/vczjk/jl5;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/c83;


# instance fields
.field public OooOoOO:Llyiahf/vczjk/oe3;

.field public OooOoo0:Llyiahf/vczjk/a93;


# virtual methods
.method public final o00O0O(Llyiahf/vczjk/a93;)V
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a83;->OooOoo0:Llyiahf/vczjk/a93;

    invoke-static {v0, p1}, Llyiahf/vczjk/v34;->OooOOo0(Ljava/lang/Object;Ljava/lang/Object;)Z

    move-result v0

    if-nez v0, :cond_0

    iput-object p1, p0, Llyiahf/vczjk/a83;->OooOoo0:Llyiahf/vczjk/a93;

    iget-object v0, p0, Llyiahf/vczjk/a83;->OooOoOO:Llyiahf/vczjk/oe3;

    invoke-interface {v0, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    :cond_0
    return-void
.end method
