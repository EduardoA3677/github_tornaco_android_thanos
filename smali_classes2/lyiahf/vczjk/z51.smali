.class public final Llyiahf/vczjk/z51;
.super Ljava/util/concurrent/CompletableFuture;
.source "SourceFile"


# instance fields
.field public final OooOOO0:Llyiahf/vczjk/c96;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/c96;)V
    .locals 0

    invoke-direct {p0}, Ljava/util/concurrent/CompletableFuture;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/z51;->OooOOO0:Llyiahf/vczjk/c96;

    return-void
.end method


# virtual methods
.method public final cancel(Z)Z
    .locals 1

    if-eqz p1, :cond_0

    iget-object v0, p0, Llyiahf/vczjk/z51;->OooOOO0:Llyiahf/vczjk/c96;

    invoke-virtual {v0}, Llyiahf/vczjk/c96;->cancel()V

    :cond_0
    invoke-super {p0, p1}, Ljava/util/concurrent/CompletableFuture;->cancel(Z)Z

    move-result p1

    return p1
.end method
