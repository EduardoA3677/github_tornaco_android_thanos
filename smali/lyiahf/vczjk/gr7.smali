.class public final Llyiahf/vczjk/gr7;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/ThreadFactory;


# virtual methods
.method public final newThread(Ljava/lang/Runnable;)Ljava/lang/Thread;
    .locals 1

    new-instance v0, Llyiahf/vczjk/fr7;

    invoke-direct {v0, p1}, Llyiahf/vczjk/fr7;-><init>(Ljava/lang/Runnable;)V

    return-object v0
.end method
