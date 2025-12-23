.class public final Llyiahf/vczjk/a86;
.super Llyiahf/vczjk/o76;
.source "SourceFile"

# interfaces
.implements Ljava/util/concurrent/Callable;


# instance fields
.field public final OooOOO0:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Ljava/lang/Object;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/a86;->OooOOO0:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final OooO0o0(Llyiahf/vczjk/j86;)V
    .locals 2

    new-instance v0, Llyiahf/vczjk/d86;

    iget-object v1, p0, Llyiahf/vczjk/a86;->OooOOO0:Ljava/lang/Object;

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/d86;-><init>(Llyiahf/vczjk/j86;Ljava/lang/Object;)V

    invoke-interface {p1, v0}, Llyiahf/vczjk/j86;->OooO0O0(Llyiahf/vczjk/nc2;)V

    invoke-virtual {v0}, Llyiahf/vczjk/d86;->run()V

    return-void
.end method

.method public final call()Ljava/lang/Object;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/a86;->OooOOO0:Ljava/lang/Object;

    return-object v0
.end method
