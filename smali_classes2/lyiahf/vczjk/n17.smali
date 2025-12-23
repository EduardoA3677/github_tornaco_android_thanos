.class public final Llyiahf/vczjk/n17;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Landroid/content/Context;

.field public final OooO0O0:Llyiahf/vczjk/wh;

.field public final OooO0OO:Llyiahf/vczjk/wh;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    const-string v0, "context"

    invoke-static {p1, v0}, Llyiahf/vczjk/v34;->OooOoO(Ljava/lang/Object;Ljava/lang/String;)V

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/n17;->OooO00o:Landroid/content/Context;

    invoke-static {p1}, Llyiahf/vczjk/o17;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v0

    check-cast v0, Llyiahf/vczjk/c27;

    iget-object v0, v0, Llyiahf/vczjk/c27;->OooO00o:Llyiahf/vczjk/ay1;

    invoke-interface {v0}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/wh;

    const/4 v2, 0x5

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    iput-object v1, p0, Llyiahf/vczjk/n17;->OooO0O0:Llyiahf/vczjk/wh;

    invoke-static {p1}, Llyiahf/vczjk/o17;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p1

    check-cast p1, Llyiahf/vczjk/c27;

    iget-object p1, p1, Llyiahf/vczjk/c27;->OooO00o:Llyiahf/vczjk/ay1;

    invoke-interface {p1}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/wh;

    const/4 v1, 0x6

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    iput-object v0, p0, Llyiahf/vczjk/n17;->OooO0OO:Llyiahf/vczjk/wh;

    return-void
.end method
