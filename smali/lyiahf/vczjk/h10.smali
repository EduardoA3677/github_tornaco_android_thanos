.class public final Llyiahf/vczjk/h10;
.super Llyiahf/vczjk/ol7;
.source "SourceFile"


# static fields
.field private static final serialVersionUID:J = 0x1L


# virtual methods
.method public final OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    iget-object v1, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/e94;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooOO0(Llyiahf/vczjk/v72;)Ljava/lang/Object;
    .locals 2

    new-instance v0, Ljava/util/concurrent/atomic/AtomicReference;

    iget-object v1, p0, Llyiahf/vczjk/ol7;->_valueDeserializer:Llyiahf/vczjk/e94;

    invoke-virtual {v1, p1}, Llyiahf/vczjk/e94;->OooO0O0(Llyiahf/vczjk/v72;)Ljava/lang/Object;

    move-result-object p1

    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicReference;-><init>(Ljava/lang/Object;)V

    return-object v0
.end method

.method public final OooOOOO(Llyiahf/vczjk/t72;)Ljava/lang/Boolean;
    .locals 0

    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    return-object p1
.end method
