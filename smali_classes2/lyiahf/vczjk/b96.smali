.class public final Llyiahf/vczjk/b96;
.super Llyiahf/vczjk/ks7;
.source "SourceFile"


# instance fields
.field public final OooOOO:Llyiahf/vczjk/uf5;

.field public final OooOOOO:J


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uf5;J)V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/b96;->OooOOO:Llyiahf/vczjk/uf5;

    iput-wide p2, p0, Llyiahf/vczjk/b96;->OooOOOO:J

    return-void
.end method


# virtual methods
.method public final OooO0Oo()J
    .locals 2

    iget-wide v0, p0, Llyiahf/vczjk/b96;->OooOOOO:J

    return-wide v0
.end method

.method public final OooO0oO()Llyiahf/vczjk/uf5;
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/b96;->OooOOO:Llyiahf/vczjk/uf5;

    return-object v0
.end method

.method public final OooOOOO()Llyiahf/vczjk/nj0;
    .locals 2

    new-instance v0, Ljava/lang/IllegalStateException;

    const-string v1, "Cannot read raw response body of a converted body."

    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw v0
.end method
