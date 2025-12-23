.class public final Llyiahf/vczjk/yv4;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Llyiahf/vczjk/gv4;


# direct methods
.method public constructor <init>(Llyiahf/vczjk/gv4;)V
    .locals 1

    const-string v0, "lazyListItem"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/yv4;->OooO00o:Llyiahf/vczjk/gv4;

    return-void
.end method


# virtual methods
.method public final OooO00o()I
    .locals 1

    iget-object v0, p0, Llyiahf/vczjk/yv4;->OooO00o:Llyiahf/vczjk/gv4;

    check-cast v0, Llyiahf/vczjk/tv4;

    iget v0, v0, Llyiahf/vczjk/tv4;->OooO00o:I

    return v0
.end method

.method public final toString()Ljava/lang/String;
    .locals 6

    invoke-virtual {p0}, Llyiahf/vczjk/yv4;->OooO00o()I

    move-result v0

    iget-object v1, p0, Llyiahf/vczjk/yv4;->OooO00o:Llyiahf/vczjk/gv4;

    move-object v2, v1

    check-cast v2, Llyiahf/vczjk/tv4;

    iget v2, v2, Llyiahf/vczjk/tv4;->OooOOOo:I

    check-cast v1, Llyiahf/vczjk/tv4;

    iget v1, v1, Llyiahf/vczjk/tv4;->OooOOo0:I

    const-string v3, "SnapperLayoutItemInfo(index="

    const-string v4, ", offset="

    const-string v5, ", size="

    invoke-static {v0, v2, v3, v4, v5}, Llyiahf/vczjk/ii5;->OooOOO0(IILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    move-result-object v0

    const-string v2, ")"

    invoke-static {v0, v1, v2}, Llyiahf/vczjk/u81;->OooOOOO(Ljava/lang/StringBuilder;ILjava/lang/String;)Ljava/lang/String;

    move-result-object v0

    return-object v0
.end method
