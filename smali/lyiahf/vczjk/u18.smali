.class public final Llyiahf/vczjk/u18;
.super Ljava/lang/Object;
.source "SourceFile"


# instance fields
.field public final OooO00o:Landroid/content/Context;

.field public final OooO0O0:Llyiahf/vczjk/f43;

.field public final OooO0OO:Llyiahf/vczjk/wh;

.field public final OooO0Oo:Llyiahf/vczjk/wh;


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 3

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Llyiahf/vczjk/u18;->OooO00o:Landroid/content/Context;

    invoke-static {p1}, Llyiahf/vczjk/h28;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object v0

    iput-object v0, p0, Llyiahf/vczjk/u18;->OooO0O0:Llyiahf/vczjk/f43;

    invoke-static {p1}, Llyiahf/vczjk/h28;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v0

    invoke-interface {v0}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object v0

    new-instance v1, Llyiahf/vczjk/wh;

    const/16 v2, 0xb

    invoke-direct {v1, v0, v2}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    iput-object v1, p0, Llyiahf/vczjk/u18;->OooO0OO:Llyiahf/vczjk/wh;

    invoke-static {p1}, Llyiahf/vczjk/mw6;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object p1

    invoke-interface {p1}, Llyiahf/vczjk/ay1;->getData()Llyiahf/vczjk/f43;

    move-result-object p1

    new-instance v0, Llyiahf/vczjk/wh;

    const/16 v1, 0xc

    invoke-direct {v0, p1, v1}, Llyiahf/vczjk/wh;-><init>(Llyiahf/vczjk/f43;I)V

    iput-object v0, p0, Llyiahf/vczjk/u18;->OooO0Oo:Llyiahf/vczjk/wh;

    return-void
.end method


# virtual methods
.method public final OooO00o(Ljava/util/ArrayList;Llyiahf/vczjk/zo1;)Ljava/lang/Object;
    .locals 7

    instance-of v0, p2, Llyiahf/vczjk/y08;

    if-eqz v0, :cond_0

    move-object v0, p2

    check-cast v0, Llyiahf/vczjk/y08;

    iget v1, v0, Llyiahf/vczjk/y08;->label:I

    const/high16 v2, -0x80000000

    and-int v3, v1, v2

    if-eqz v3, :cond_0

    sub-int/2addr v1, v2

    iput v1, v0, Llyiahf/vczjk/y08;->label:I

    goto :goto_0

    :cond_0
    new-instance v0, Llyiahf/vczjk/y08;

    invoke-direct {v0, p0, p2}, Llyiahf/vczjk/y08;-><init>(Llyiahf/vczjk/u18;Llyiahf/vczjk/zo1;)V

    :goto_0
    iget-object p2, v0, Llyiahf/vczjk/y08;->result:Ljava/lang/Object;

    sget-object v1, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    iget v2, v0, Llyiahf/vczjk/y08;->label:I

    const/4 v3, 0x1

    if-eqz v2, :cond_2

    if-ne v2, v3, :cond_1

    iget-object p1, v0, Llyiahf/vczjk/y08;->L$0:Ljava/lang/Object;

    check-cast p1, Ljava/util/Iterator;

    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    goto :goto_1

    :cond_1
    new-instance p1, Ljava/lang/IllegalStateException;

    const-string p2, "call to \'resume\' before \'invoke\' with coroutine"

    invoke-direct {p1, p2}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p1

    :cond_2
    invoke-static {p2}, Llyiahf/vczjk/rl6;->OooOoo0(Ljava/lang/Object;)V

    invoke-virtual {p1}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    move-result-object p1

    :cond_3
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    move-result p2

    sget-object v2, Llyiahf/vczjk/z8a;->OooO00o:Llyiahf/vczjk/z8a;

    if-eqz p2, :cond_5

    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    move-result-object p2

    check-cast p2, Ltornaco/apps/thanox/core/proto/common/AppPkg;

    iput-object p1, v0, Llyiahf/vczjk/y08;->L$0:Ljava/lang/Object;

    iput v3, v0, Llyiahf/vczjk/y08;->label:I

    iget-object v4, p0, Llyiahf/vczjk/u18;->OooO00o:Landroid/content/Context;

    invoke-static {v4}, Llyiahf/vczjk/h28;->OooO00o(Landroid/content/Context;)Llyiahf/vczjk/ay1;

    move-result-object v4

    new-instance v5, Llyiahf/vczjk/v08;

    const/4 v6, 0x0

    invoke-direct {v5, p2, v6}, Llyiahf/vczjk/v08;-><init>(Ltornaco/apps/thanox/core/proto/common/AppPkg;Llyiahf/vczjk/yo1;)V

    invoke-interface {v4, v5, v0}, Llyiahf/vczjk/ay1;->OooO00o(Llyiahf/vczjk/ze3;Llyiahf/vczjk/yo1;)Ljava/lang/Object;

    move-result-object p2

    sget-object v4, Llyiahf/vczjk/yr1;->OooOOO0:Llyiahf/vczjk/yr1;

    if-ne p2, v4, :cond_4

    move-object v2, p2

    :cond_4
    if-ne v2, v1, :cond_3

    return-object v1

    :cond_5
    return-object v2
.end method
