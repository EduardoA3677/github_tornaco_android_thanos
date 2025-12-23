.class public final Llyiahf/vczjk/wv8;
.super Llyiahf/vczjk/d39;
.source "SourceFile"


# instance fields
.field public OooO0OO:D


# direct methods
.method public constructor <init>(JD)V
    .locals 0

    invoke-direct {p0, p1, p2}, Llyiahf/vczjk/d39;-><init>(J)V

    iput-wide p3, p0, Llyiahf/vczjk/wv8;->OooO0OO:D

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/d39;)V
    .locals 2

    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableDoubleStateImpl.DoubleStateStateRecord"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/wv8;

    iget-wide v0, p1, Llyiahf/vczjk/wv8;->OooO0OO:D

    iput-wide v0, p0, Llyiahf/vczjk/wv8;->OooO0OO:D

    return-void
.end method

.method public final OooO0O0(J)Llyiahf/vczjk/d39;
    .locals 3

    new-instance v0, Llyiahf/vczjk/wv8;

    iget-wide v1, p0, Llyiahf/vczjk/wv8;->OooO0OO:D

    invoke-direct {v0, p1, p2, v1, v2}, Llyiahf/vczjk/wv8;-><init>(JD)V

    return-object v0
.end method
