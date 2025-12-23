.class public final Llyiahf/vczjk/e10;
.super Llyiahf/vczjk/a59;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0Oo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Ljava/util/concurrent/atomic/AtomicBoolean;

    const-class v1, Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {p0, p1, p2, v1}, Llyiahf/vczjk/m49;->OooOoo(Llyiahf/vczjk/v72;Llyiahf/vczjk/eb4;Ljava/lang/Class;)Z

    move-result p1

    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicBoolean;-><init>(Z)V

    return-object v0
.end method
