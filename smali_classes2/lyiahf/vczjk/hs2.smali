.class public abstract Llyiahf/vczjk/hs2;
.super Llyiahf/vczjk/qr1;
.source "SourceFile"

# interfaces
.implements Ljava/io/Closeable;
.implements Ljava/lang/AutoCloseable;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    const-string v0, "baseKey"

    sget-object v1, Llyiahf/vczjk/qr1;->OooOOO:Llyiahf/vczjk/pr1;

    invoke-static {v1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    return-void
.end method


# virtual methods
.method public abstract o0000()Ljava/util/concurrent/Executor;
.end method
