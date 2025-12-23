.class public final Llyiahf/vczjk/v80;
.super Ljava/lang/Object;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/u22;


# instance fields
.field public final OooOOO:Llyiahf/vczjk/v74;

.field public final OooOOO0:Llyiahf/vczjk/ky4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/ky4;Llyiahf/vczjk/v74;)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/v80;->OooOOO0:Llyiahf/vczjk/ky4;

    iput-object p2, p0, Llyiahf/vczjk/v80;->OooOOO:Llyiahf/vczjk/v74;

    return-void
.end method


# virtual methods
.method public final onDestroy(Llyiahf/vczjk/uy4;)V
    .locals 1

    iget-object p1, p0, Llyiahf/vczjk/v80;->OooOOO:Llyiahf/vczjk/v74;

    const/4 v0, 0x0

    invoke-interface {p1, v0}, Llyiahf/vczjk/v74;->OooO0oO(Ljava/util/concurrent/CancellationException;)V

    return-void
.end method
