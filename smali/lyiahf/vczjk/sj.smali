.class public final Llyiahf/vczjk/sj;
.super Llyiahf/vczjk/rm4;
.source "SourceFile"

# interfaces
.implements Llyiahf/vczjk/oe3;


# instance fields
.field final synthetic $targetOffset:Llyiahf/vczjk/oe3;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/oe3;"
        }
    .end annotation
.end field

.field final synthetic this$0:Llyiahf/vczjk/uj;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Llyiahf/vczjk/uj;"
        }
    .end annotation
.end field


# direct methods
.method public constructor <init>(Llyiahf/vczjk/uj;Llyiahf/vczjk/oe3;)V
    .locals 0

    iput-object p1, p0, Llyiahf/vczjk/sj;->this$0:Llyiahf/vczjk/uj;

    iput-object p2, p0, Llyiahf/vczjk/sj;->$targetOffset:Llyiahf/vczjk/oe3;

    const/4 p1, 0x1

    invoke-direct {p0, p1}, Llyiahf/vczjk/rm4;-><init>(I)V

    return-void
.end method


# virtual methods
.method public final OooO0o(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 11

    check-cast p1, Ljava/lang/Number;

    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    move-result p1

    iget-object v0, p0, Llyiahf/vczjk/sj;->this$0:Llyiahf/vczjk/uj;

    iget-object v1, v0, Llyiahf/vczjk/uj;->OooO0o0:Llyiahf/vczjk/js5;

    iget-object v0, v0, Llyiahf/vczjk/uj;->OooO00o:Llyiahf/vczjk/bz9;

    iget-object v0, v0, Llyiahf/vczjk/bz9;->OooO0Oo:Llyiahf/vczjk/qs5;

    check-cast v0, Llyiahf/vczjk/fw8;

    invoke-virtual {v0}, Llyiahf/vczjk/fw8;->getValue()Ljava/lang/Object;

    move-result-object v0

    invoke-virtual {v1, v0}, Llyiahf/vczjk/js5;->OooO0oO(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/p29;

    if-eqz v0, :cond_0

    invoke-interface {v0}, Llyiahf/vczjk/p29;->getValue()Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/b24;

    iget-wide v0, v0, Llyiahf/vczjk/b24;->OooO00o:J

    goto :goto_0

    :cond_0
    const-wide/16 v0, 0x0

    :goto_0
    iget-object v2, p0, Llyiahf/vczjk/sj;->$targetOffset:Llyiahf/vczjk/oe3;

    iget-object v3, p0, Llyiahf/vczjk/sj;->this$0:Llyiahf/vczjk/uj;

    int-to-long v4, p1

    const/16 v6, 0x20

    shl-long v7, v4, v6

    const-wide v9, 0xffffffffL

    and-long/2addr v4, v9

    or-long/2addr v4, v7

    invoke-static {v3, v4, v5, v0, v1}, Llyiahf/vczjk/uj;->OooO0Oo(Llyiahf/vczjk/uj;JJ)J

    move-result-wide v0

    shr-long/2addr v0, v6

    long-to-int v0, v0

    neg-int v0, v0

    sub-int/2addr v0, p1

    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object p1

    invoke-interface {v2, p1}, Llyiahf/vczjk/oe3;->OooO0o(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object p1

    check-cast p1, Ljava/lang/Integer;

    return-object p1
.end method
