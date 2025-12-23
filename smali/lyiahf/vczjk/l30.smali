.class public final Llyiahf/vczjk/l30;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Landroid/content/Context;

.field public final OooO0O0:Llyiahf/vczjk/f43;

.field public final OooO0OO:Llyiahf/vczjk/wh;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 2

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/l30;->OooO00o:Landroid/content/Context;

    invoke-static {p1}, Llyiahf/vczjk/p30;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/l30;->OooO0O0:Llyiahf/vczjk/f43;

    invoke-static {p1}, Llyiahf/vczjk/p30;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/wh;

    const/4 v1, 0x3

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    iput-object v0, p0, Llyiahf/vczjk/l30;->OooO0OO:Llyiahf/vczjk/wh;

    return-void
.end method
