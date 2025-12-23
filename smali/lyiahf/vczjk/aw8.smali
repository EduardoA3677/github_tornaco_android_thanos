.class public final Llyiahf/vczjk/aw8;
.super Llyiahf/vczjk/d39;
.source "SourceFile"


# instance fields
.field public OooO0OO:I


# direct methods
.method public constructor <init>(IJ)V
    .locals 0

    invoke-direct {p0, p2, p3}, Llyiahf/vczjk/d39;-><init>(J)V

    iput p1, p0, Llyiahf/vczjk/aw8;->OooO0OO:I

    return-void
.end method


# virtual methods
.method public final OooO00o(Llyiahf/vczjk/d39;)V
    .locals 1

    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableIntStateImpl.IntStateStateRecord"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOo(Ljava/lang/Object;Ljava/lang/String;)V

    check-cast p1, Llyiahf/vczjk/aw8;

    iget p1, p1, Llyiahf/vczjk/aw8;->OooO0OO:I

    iput p1, p0, Llyiahf/vczjk/aw8;->OooO0OO:I

    return-void
.end method

.method public final OooO0O0(J)Llyiahf/vczjk/d39;
    .locals 2

    new-instance v0, Llyiahf/vczjk/aw8;

    iget v1, p0, Llyiahf/vczjk/aw8;->OooO0OO:I

    invoke-direct {v0, v1, p1, p2}, Llyiahf/vczjk/aw8;-><init>(IJ)V

    return-object v0
.end method
